package org.steer.core;

import java.io.IOException;
import java.net.*;
import java.util.*;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Authenticated TCP-control-owned RFC1928 UDP relay. No public resolver or
 * physical route is available here. UDP itself has no credentials: source IP
 * must match the TCP peer, then one client source port is pinned for its life.
 * This is loopback-only, not cryptographic datagram authentication or LAN mode.
 * The supplied executor's actual termination is the enclosing owner's barrier. */
public final class SocksUdpAssociation implements AutoCloseable {
    public interface Channel extends AutoCloseable {
        void send(byte[] payload)throws IOException;
        /** Connected peer only, no truncation; a bounded timeout is mandatory. */
        byte[] receive()throws IOException;
        @Override void close();
    }
    public interface Dialer {
        Channel open(ProxyHandshake.Target target,AuthenticatedProxy.Cancellation cancellation)throws IOException;
        /** Called for EVERY accepted datagram AND response, including cached target channels.
         * Actual VPN implementation rechecks owner identity; model dialers may
         * only check cancellation and do not establish Android ownership. */
        default void validateClient(AuthenticatedProxy.Cancellation cancellation)throws IOException{
            if(cancellation.cancelled())throw new IOException("UDP client retired");
        }
    }
    private static final long FLOW_IDLE=TimeUnit.SECONDS.toNanos(60);
    private final DatagramSocket relay;
    private final InetAddress peer;
    private final Dialer dialer;
    private final AuthenticatedProxy.Cancellation cancellation;
    private final Runnable progress;
    private final Executor readers;
    private final AtomicBoolean closed=new AtomicBoolean();
    private final Map<String,Flow> flows=new HashMap<>();
    private int clientPort;
    public SocksUdpAssociation(InetAddress bind,InetAddress peer,ProxyHandshake.UdpEndpoint endpoint,
            Dialer dialer,AuthenticatedProxy.Cancellation cancellation,Runnable progress,Executor readers)throws IOException{
        if(bind==null||!bind.isLoopbackAddress()||peer==null||!peer.isLoopbackAddress()||endpoint==null||
                dialer==null||cancellation==null||progress==null||readers==null)
            throw new IllegalArgumentException("Owned loopback association required");
        byte[] requested=endpoint.address();boolean unspecified=true;
        for(byte value:requested)unspecified&=value==0;
        if(!unspecified&&!Arrays.equals(requested,peer.getAddress()))throw new IOException("UDP client address rejected");
        if(requested.length!=peer.getAddress().length)throw new IOException("UDP client family mismatch");
        this.peer=peer;this.dialer=dialer;this.cancellation=cancellation;this.progress=progress;this.readers=readers;
        clientPort=endpoint.port;
        relay=new DatagramSocket(null);
        try{relay.bind(new InetSocketAddress(bind,0));relay.setSoTimeout(500);}
        catch(IOException|RuntimeException failure){relay.close();throw failure;}
    }
    public ProxyHandshake.Target bound(){return ProxyHandshake.Target.numeric(relay.getLocalAddress().getAddress(),relay.getLocalPort());}
    private boolean cancelled(){return closed.get()||cancellation.cancelled();}
    /** Run on an owned worker; the TCP control reader closes this on EOF. */
    public void relay()throws IOException{
        byte[] block=new byte[SocksUdpPacket.MAX_PACKET+1];
        while(!cancelled()){
            DatagramPacket input=new DatagramPacket(block,block.length);
            try{relay.receive(input);}catch(SocketTimeoutException timeout){continue;}
            if(!peer.equals(input.getAddress())||input.getPort()<1||input.getLength()>SocksUdpPacket.MAX_PACKET)continue;
            SocksUdpPacket.Packet packet;
            try{packet=SocksUdpPacket.parse(block,input.getLength());}catch(IOException refused){continue;}
            synchronized(this){
                if(cancelled()||(clientPort!=0&&clientPort!=input.getPort()))continue;
            }
            AuthenticatedProxy.Cancellation observed;
            try{
                FlowIdentity tuple=FlowIdentity.of(17,input.getAddress().getAddress(),input.getPort(),relay.getLocalAddress().getAddress(),relay.getLocalPort());
                observed=AuthenticatedProxy.observedDatagram(cancellation,tuple);
                dialer.validateClient(observed);
            }catch(IOException|IllegalArgumentException unavailable){continue;}
            synchronized(this){
                if(cancelled()||(clientPort!=0&&clientPort!=input.getPort()))continue;
                if(clientPort==0)clientPort=input.getPort(); // do not pin an owner-rejected source port
            }
            Flow flow=find(packet.target,observed);
            if(flow==null)continue;
            if(cancelled())break;
            try{flow.channel.send(packet.payload());flow.activity=System.nanoTime();progress.run();}
            catch(IOException failure){flow.close();}
        }
    }
    private Flow find(ProxyHandshake.Target target,AuthenticatedProxy.Cancellation observed)throws IOException{
        String key=target.domain==null?Arrays.toString(target.address())+":"+target.port:"d/"+target.domain+":"+target.port;
        synchronized(this){
            if(cancelled())return null;
            Flow existing=flows.get(key);if(existing!=null)return existing;
            if(flows.size()>=8)return null;
        }
        Channel channel;
        try{channel=dialer.open(target,AuthenticatedProxy.child(observed,()->cancelled()));}catch(IOException refused){return null;}
        if(channel==null)return null;
        Flow flow=new Flow(key,target,channel,observed);
        synchronized(this){
            if(cancelled()){channel.close();return null;}
            flows.put(key,flow);
            try{readers.execute(flow);}catch(RejectedExecutionException busy){flow.close();return null;}
        }
        return flow;
    }
    private final class Flow implements Runnable,AutoCloseable{
        final String key;final ProxyHandshake.Target target;final Channel channel;
        final AuthenticatedProxy.Cancellation client;
        final AtomicBoolean ended=new AtomicBoolean();volatile long activity=System.nanoTime();
        Flow(String key,ProxyHandshake.Target target,Channel channel,AuthenticatedProxy.Cancellation observed){
            this.key=key;this.target=target;this.channel=channel;client=AuthenticatedProxy.child(observed,()->cancelled()||ended.get());
        }
        public void run(){
            try{
                while(!cancelled()&&!ended.get()&&System.nanoTime()-activity<FLOW_IDLE){
                    byte[] payload;
                    try{payload=channel.receive();}catch(SocketTimeoutException timeout){continue;}
                    if(payload==null)throw new IOException("UDP channel closed");
                    byte[] packet=SocksUdpPacket.encode(target,payload);int port;
                    synchronized(SocksUdpAssociation.this){if(cancelled()||ended.get())return;port=clientPort;}
                    if(port<1)return;
                    // Otherwise an in-flight reply could reach a different app
                    // that recycled the UDP port after the last request.
                    dialer.validateClient(client);
                    if(cancelled()||ended.get())return;
                    relay.send(new DatagramPacket(packet,packet.length,peer,port));activity=System.nanoTime();progress.run();
                }
            }catch(IOException failure){/* no datagram success/error claim to client */}
            finally{close();}
        }
        public void close(){
            if(!ended.compareAndSet(false,true))return;
            channel.close();synchronized(SocksUdpAssociation.this){if(flows.get(key)==this)flows.remove(key);}
        }
    }
    @Override public void close(){
        if(!closed.compareAndSet(false,true))return;relay.close();
        List<Flow> owned;synchronized(this){owned=new ArrayList<>(flows.values());flows.clear();}
        for(Flow flow:owned)flow.close();
    }
}
