package org.steer.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

/** Owned loopback-only authenticated HTTP/SOCKS frontend. No resolver, direct
 * dial, VPN creation or native capability admission lives here. The host must
 * provide a policy-enforcing protected Dialer, including its own dial deadline.
 * Explicit-VPN/native ownership is supplied separately; this source is not an
 * advertised or verified module capability yet. */
public final class AuthenticatedProxy implements AutoCloseable {
    public interface Transport extends AutoCloseable {
        InputStream input() throws IOException;
        OutputStream output() throws IOException;
        ProxyHandshake.Target bound();
        void shutdownOutput() throws IOException;
        /** Must promptly abort blocking IO; do not wait for TLS close_notify. */
        @Override void close() throws IOException;
    }
    public interface Cancellation { boolean cancelled(); }
    public interface OriginalClient extends Cancellation {
        /** Accepted original TCP CLIENT tuple, not the listener/worker socket. */
        FlowIdentity originalClient() throws IOException;
        default void verifyOwner(int uid,java.util.Set<String> packages)throws IOException{throw new IOException("Authenticated client lifetime fence unavailable");}
    }
    public interface OriginalDatagram extends OriginalClient {
        /** OBSERVED UDP client -> relay tuple, not the TCP control source port
         * or the remote target encoded inside the SOCKS UDP packet. */
        FlowIdentity originalDatagram() throws IOException;
    }
    static Cancellation child(Cancellation owner,Cancellation scope){
        if(owner instanceof OriginalDatagram)return new OriginalDatagram(){
            public boolean cancelled(){return owner.cancelled()||scope.cancelled();}
            public FlowIdentity originalClient()throws IOException{if(cancelled())throw new IOException("Original client retired");return ((OriginalDatagram)owner).originalClient();}
            public FlowIdentity originalDatagram()throws IOException{if(cancelled())throw new IOException("Original datagram retired");return ((OriginalDatagram)owner).originalDatagram();}
            public void verifyOwner(int uid,java.util.Set<String> packages)throws IOException{if(cancelled())throw new IOException("Original client retired");((OriginalDatagram)owner).verifyOwner(uid,packages);}
        };
        if(!(owner instanceof OriginalClient))return ()->owner.cancelled()||scope.cancelled();
        return new OriginalClient(){
            public boolean cancelled(){return owner.cancelled()||scope.cancelled();}
            public FlowIdentity originalClient()throws IOException{
                if(cancelled())throw new IOException("Original client retired");
                return ((OriginalClient)owner).originalClient();
            }
            public void verifyOwner(int uid,java.util.Set<String> packages)throws IOException{if(cancelled())throw new IOException("Original client retired");((OriginalClient)owner).verifyOwner(uid,packages);}
        };
    }
    static Cancellation observedDatagram(Cancellation owner,FlowIdentity observed){
        if(owner==null||observed==null||observed.protocol!=17)throw new IllegalArgumentException("Observed UDP tuple required");
        return new OriginalDatagram(){
            public boolean cancelled(){return owner.cancelled();}
            public FlowIdentity originalClient()throws IOException{
                if(cancelled()||!(owner instanceof OriginalClient))throw new IOException("Authenticated TCP control unavailable");
                return ((OriginalClient)owner).originalClient();
            }
            public FlowIdentity originalDatagram()throws IOException{if(cancelled())throw new IOException("Original datagram retired");return observed;}
            public void verifyOwner(int uid,java.util.Set<String> packages)throws IOException{
                if(cancelled()||!(owner instanceof OriginalClient))throw new IOException("Authenticated TCP control unavailable");
                ((OriginalClient)owner).verifyOwner(uid,packages);
            }
        };
    }
    public interface Dialer {
        /** Actual VPN implementation binds fresh kernel identity BEFORE any
         * request/association success. Pure model dialers establish no UID proof. */
        default void authenticated(OriginalClient client)throws IOException{if(client.cancelled())throw new IOException("Authenticated client retired");}
        /** No platform DNS/direct fallback. Late results are closed by the owner. */
        Transport connect(ProxyHandshake.Target target, Cancellation cancellation) throws IOException;
    }
    private final ProxyListener listener;
    private final ProxyHandshake.Credentials credentials;
    private final Dialer dialer;
    private final SocksUdpAssociation.Dialer datagrams;
    private final long handshakeNanos, idleNanos;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final Object admission = new Object();
    private final Set<Connection> connections = ConcurrentHashMap.newKeySet();
    private final ThreadPoolExecutor workers = pool("steer-proxy-client");
    private final ThreadPoolExecutor uploads = pool("steer-proxy-upload");
    private final ThreadPoolExecutor udpReaders = new ThreadPoolExecutor(0,128,15,TimeUnit.SECONDS,
        new SynchronousQueue<Runnable>(),r->{Thread thread=new Thread(r,"steer-proxy-udp");thread.setDaemon(true);return thread;});
    private final ScheduledExecutorService deadlines = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r,"steer-proxy-deadlines"); thread.setDaemon(true); return thread;
    });
    private final Thread acceptor;

    private static ThreadPoolExecutor pool(String name) {
        return new ThreadPoolExecutor(0,16,15,TimeUnit.SECONDS,new SynchronousQueue<Runnable>(),r -> {
            Thread thread=new Thread(r,name);thread.setDaemon(true);return thread;
        });
    }
    public AuthenticatedProxy(InetAddress bind, int port, byte[] user, byte[] password,
                              Dialer dialer, int handshakeMillis, int idleMillis) throws IOException {
        this(bind,port,user,password,dialer,null,handshakeMillis,idleMillis);
    }
    public AuthenticatedProxy(InetAddress bind,int port,byte[] user,byte[] password,
                              Dialer dialer,SocksUdpAssociation.Dialer datagrams,int handshakeMillis,int idleMillis)throws IOException{
        this(ProxyListener.loopback(bind,port),user,password,dialer,datagrams,handshakeMillis,idleMillis);
    }
    public AuthenticatedProxy(ProxyListener.Factory factory,byte[] user,byte[] password,
                              Dialer dialer,SocksUdpAssociation.Dialer datagrams,int handshakeMillis,int idleMillis)throws IOException{
        if(factory==null || dialer==null ||
                handshakeMillis<100 || handshakeMillis>30000 || idleMillis<100 || idleMillis>600000)
            throw new IllegalArgumentException("Bounded loopback proxy configuration required");
        credentials=new ProxyHandshake.Credentials(user,password);
        this.dialer=dialer;this.datagrams=datagrams;handshakeNanos=TimeUnit.MILLISECONDS.toNanos(handshakeMillis);
        idleNanos=TimeUnit.MILLISECONDS.toNanos(idleMillis);
        ProxyListener pending=null;
        try {
            pending=factory.open();
            if(pending==null||pending.getInetAddress()==null||!pending.getInetAddress().isLoopbackAddress()||pending.getLocalPort()<1||pending.getLocalPort()>65535)
                throw new IOException("Owned loopback listener required");
        }
        catch(IOException|RuntimeException error) { credentials.close();workers.shutdownNow();uploads.shutdownNow();udpReaders.shutdownNow();deadlines.shutdownNow();if(pending!=null)pending.close();throw error; }
        listener=pending;
        acceptor=new Thread(this::accept,"steer-proxy-accept");acceptor.setDaemon(true);
        deadlines.scheduleWithFixedDelay(this::expire,50,50,TimeUnit.MILLISECONDS);
        acceptor.start();
    }
    public int port() { return listener.getLocalPort(); }
    private void accept() {
        while(!closed.get()) {
            ProxyListener.Client socket=null;
            try {
                socket=listener.accept();
                synchronized(admission) {
                    if(closed.get() || !socket.getInetAddress().isLoopbackAddress()) { socket.close();continue; }
                    Connection connection=new Connection(socket);connections.add(connection);
                    try { workers.execute(connection); }
                    catch(RejectedExecutionException busy) { connection.close(); }
                }
            } catch(IOException error) {
                if(socket!=null)try{socket.close();}catch(IOException ignored){}
                if(!closed.get())close();
            }
        }
    }
    private void expire() {
        long now=System.nanoTime();
        for(Connection connection:connections) {
            long bound=connection.connected ? idleNanos : handshakeNanos;
            if(connection.cancelled()||now-connection.activity>=bound)connection.close();
        }
    }
    private final class Connection implements Runnable, OriginalClient {
        final ProxyClientIdentity identity=new ProxyClientIdentity();
        final ProxyListener.Client client;
        final AtomicBoolean ended=new AtomicBoolean();
        volatile long activity=System.nanoTime();
        volatile boolean connected;
        volatile boolean authenticated;
        private Transport upstream;
        private SocksUdpAssociation udp;
        Connection(ProxyListener.Client client) { this.client=client; }
        @Override public boolean cancelled() { return ended.get() || closed.get() || identity.retired(); }
        @Override public void verifyOwner(int uid,java.util.Set<String> packages)throws IOException{
            if(!authenticated||cancelled())throw new IOException("Authenticated client retired");identity.verify(uid,packages);
        }
        @Override public FlowIdentity originalClient()throws IOException{
            if(!authenticated||cancelled())throw new IOException("Authenticated original client unavailable");
            // Reverse the accepted socket's local/remote view: lookup must name
            // the CLIENT socket, not the server's accepted socket/worker UID.
            return FlowIdentity.of(6,client.getInetAddress().getAddress(),client.getPort(),
                client.getLocalAddress().getAddress(),client.getLocalPort());
        }
        private synchronized boolean attach(Transport transport) {
            if(cancelled()) { closeTransport(transport);return false; }
            upstream=transport;return true;
        }
        @Override public void run() {
            ProxyHandshake.Request request=null;boolean announced=false;
            try {
                if(cancelled())return;
                client.setTcpNoDelay(true);
                client.setSoTimeout((int)TimeUnit.NANOSECONDS.toMillis(handshakeNanos));
                InputStream input=client.getInputStream();OutputStream output=client.getOutputStream();
                request=ProxyHandshake.read(input,output,credentials,datagrams!=null);
                if(request==null || cancelled())return;
                authenticated=true;
                dialer.authenticated(this);
                if(request.protocol==ProxyHandshake.Protocol.SOCKS5_UDP_ASSOCIATE){
                    SocksUdpAssociation association=new SocksUdpAssociation(listener.getInetAddress(),client.getInetAddress(),
                        request.udpEndpoint,datagrams,this,()->activity=System.nanoTime(),udpReaders);
                    synchronized(this){if(cancelled()){association.close();return;}udp=association;}
                    request.connected(output,association.bound());announced=true;connected=true;activity=System.nanoTime();client.setSoTimeout(0);
                    uploads.execute(()->{try{association.relay();}catch(IOException ignored){}finally{close();}});
                    // RFC1928 association lifetime belongs to this TCP control
                    // connection. Application bytes here are not another tunnel.
                    input.read();return;
                }
                Transport transport=dialer.connect(request.target,this);
                if(transport==null)throw new IOException("Proxy dial unavailable");
                if(!attach(transport))return;
                ProxyHandshake.Target bound=transport.bound();
                if(bound==null || bound.address()==null)throw new IOException("Proxy bound endpoint unavailable");
                if(cancelled())return;
                request.connected(output,bound);
                byte[] forwarded=request.forwardedHead();
                if(forwarded!=null){transport.output().write(forwarded);transport.output().flush();}
                announced=true;connected=true;activity=System.nanoTime();
                client.setSoTimeout(0);
                final ProxyHandshake.Request accepted=request;
                Future<?> upload=uploads.submit(() -> {
                    try {
                        if(accepted.protocol==ProxyHandshake.Protocol.HTTP_FORWARD)
                            HttpForwardBody.copy(accepted,input,transport.output(),this,()->activity=System.nanoTime());
                        else copy(input,transport.output());
                        transport.shutdownOutput();
                    }
                    catch(IOException error) { close(); }
                });
                copy(transport.input(),output);
                client.shutdownOutput();
                if(accepted.protocol==ProxyHandshake.Protocol.HTTP_FORWARD)return; // exactly one origin request
                // Preserve client upload after peer half-close. The shared idle
                // deadline/owner STOP closes both legs, not a fixed join timer.
                while(!upload.isDone() && !cancelled()) {
                    try { upload.get(100,TimeUnit.MILLISECONDS); }
                    catch(TimeoutException waiting) { /* idle deadline owns expiry */ }
                }
            } catch(Exception error) {
                if(request!=null && !announced && !cancelled())try{request.failed(client.getOutputStream());}catch(IOException ignored){}
            } finally { close(); }
        }
        private void copy(InputStream input,OutputStream output) throws IOException {
            byte[] block=new byte[16384];int count;
            while(!cancelled() && (count=input.read(block))!=-1) {
                if(count==0)continue;
                output.write(block,0,count);output.flush();activity=System.nanoTime();
            }
        }
        synchronized void close() {
            if(!ended.compareAndSet(false,true))return;
            identity.close();
            try { client.close(); } catch(IOException ignored) {}
            closeTransport(upstream);upstream=null;connections.remove(this);
            if(udp!=null){udp.close();udp=null;}
        }
    }
    private static void closeTransport(Transport transport) {
        if(transport!=null)try{transport.close();}catch(Exception ignored){}
    }
    @Override public void close() {
        synchronized(admission) {
            if(!closed.compareAndSet(false,true))return;
            try{listener.close();}catch(IOException ignored){}
            for(Connection connection:connections)connection.close();
        }
        credentials.close();workers.shutdownNow();uploads.shutdownNow();udpReaders.shutdownNow();deadlines.shutdownNow();
    }
    /** STOP initiates closure; only this separate bounded barrier proves exit.
     * A host dialer which ignores cancellation cannot be reported as stopped. */
    public boolean awaitClosed(int millis) throws InterruptedException {
        if(!closed.get() || millis<1 || millis>30000)throw new IllegalStateException("Closed owner and bounded wait required");
        long until=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(millis);
        workers.awaitTermination(Math.max(0,until-System.nanoTime()),TimeUnit.NANOSECONDS);
        uploads.awaitTermination(Math.max(0,until-System.nanoTime()),TimeUnit.NANOSECONDS);
        udpReaders.awaitTermination(Math.max(0,until-System.nanoTime()),TimeUnit.NANOSECONDS);
        deadlines.awaitTermination(Math.max(0,until-System.nanoTime()),TimeUnit.NANOSECONDS);
        long remaining=until-System.nanoTime();
        if(remaining>0 && Thread.currentThread()!=acceptor)acceptor.join(Math.max(1,TimeUnit.NANOSECONDS.toMillis(remaining)));
        return workers.isTerminated() && uploads.isTerminated() && udpReaders.isTerminated() && deadlines.isTerminated() && !acceptor.isAlive();
    }
}
