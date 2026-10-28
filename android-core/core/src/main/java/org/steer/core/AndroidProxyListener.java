package org.steer.core;

import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructTimeval;
import java.io.IOException;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

/** SOURCE ONLY public API29 adapter, not evidence of protection/IO/STOP.
 * Owns accepted PFDs directly, with no hidden Socket constructor or reflection.
 * Public APIs: https://developer.android.com/reference/android/system/Os
 * Timeout option is API29; module/core already require29, never fcntlInt30. */
public final class AndroidProxyListener implements ProxyListener {
    private final ProtectedTcpListener listener;
    private final AuthenticatedProxy.Cancellation cancellation;
    public AndroidProxyListener(InetAddress address,int port,ProtectedTcpListener.Preparation preparation,AuthenticatedProxy.Cancellation cancellation)throws IOException{
        this.cancellation=cancellation;listener=new ProtectedTcpListener(address,port,preparation,cancellation);
    }
    public InetAddress getInetAddress(){return listener.bound().getAddress();}
    public int getLocalPort(){return listener.bound().getPort();}
    public Client accept()throws IOException{
        ParcelFileDescriptor accepted=listener.accept();
        try{return new FdClient(accepted,cancellation);}
        catch(IOException|RuntimeException failure){accepted.close();throw failure;}
    }
    public void close(){listener.close();}
    @Override public String toString(){return "AndroidProxyListener(redacted)";}

    private static final class FdClient implements Client {
        private final ParcelFileDescriptor owner;
        private final Object ownership=new Object();
        private final AuthenticatedProxy.Cancellation cancellation;
        private final InetSocketAddress local,peer;
        private final AtomicBoolean ended=new AtomicBoolean(),outputEnded=new AtomicBoolean();
        FdClient(ParcelFileDescriptor owner,AuthenticatedProxy.Cancellation cancellation)throws IOException{
            this.owner=owner;this.cancellation=cancellation;
            try{
                local=(InetSocketAddress)Os.getsockname(owner.getFileDescriptor());
                peer=(InetSocketAddress)Os.getpeername(owner.getFileDescriptor());
                if(!local.getAddress().isLoopbackAddress()||!peer.getAddress().isLoopbackAddress()||local.getPort()<1||peer.getPort()<1)
                    throw new IOException("Original loopback socket endpoints required");
                check();
            }catch(ErrnoException failure){throw new IOException("Accepted socket endpoints unavailable");}
        }
        private void check()throws IOException{
            if(ended.get()||cancellation.cancelled()||Thread.currentThread().isInterrupted())throw new IOException("Accepted socket retired");
        }
        private ParcelFileDescriptor operation()throws IOException{
            // Pin this socket while a syscall is in flight. Closing/recycling
            // the owner's integer cannot redirect that operation to a new fd.
            synchronized(ownership){check();return owner.dup();}
        }
        private static void bounds(byte[] bytes,int offset,int count){
            if(bytes==null)throw new NullPointerException();
            if(offset<0||count<0||offset>bytes.length-count)throw new IndexOutOfBoundsException();
        }
        private IOException ioFailure(ErrnoException failure){
            if(failure.errno==OsConstants.EAGAIN)return new SocketTimeoutException("Accepted socket timeout");
            return new IOException("Accepted socket IO unavailable");
        }
        public InetAddress getInetAddress(){return peer.getAddress();}
        public int getPort(){return peer.getPort();}
        public InetAddress getLocalAddress(){return local.getAddress();}
        public int getLocalPort(){return local.getPort();}
        public void setTcpNoDelay(boolean enabled)throws IOException{
            synchronized(ownership){check();try{Os.setsockoptInt(owner.getFileDescriptor(),OsConstants.IPPROTO_TCP,OsConstants.TCP_NODELAY,enabled?1:0);}
            catch(ErrnoException failure){throw new IOException("Accepted socket option unavailable");}
            }
        }
        public void setSoTimeout(int millis)throws IOException{
            if(millis<0||millis>600000)throw new IllegalArgumentException("Bounded read timeout required");
            synchronized(ownership){check();try{Os.setsockoptTimeval(owner.getFileDescriptor(),OsConstants.SOL_SOCKET,OsConstants.SO_RCVTIMEO,StructTimeval.fromMillis(millis));}
            catch(ErrnoException failure){throw new IOException("Accepted socket timeout unavailable");}
            }
        }
        // Keep handshake single-byte reads from allocating a duplicate/syscall
        // per byte. The SAME bounded buffer is retained for the subsequent body.
        private final InputStream input=new BufferedInputStream(new InputStream(){
            public int read()throws IOException{byte[] single=new byte[1];int count=read(single,0,1);return count<0?-1:single[0]&255;}
            public int read(byte[] bytes,int offset,int count)throws IOException{
                bounds(bytes,offset,count);if(count==0)return 0;check();
                try(ParcelFileDescriptor pinned=operation()){
                    int received=Os.read(pinned.getFileDescriptor(),bytes,offset,count);check();return received==0?-1:received;
                }
                catch(ErrnoException failure){throw ioFailure(failure);}
            }
            public void close()throws IOException{FdClient.this.close();}
        },8192){
            // Buffered bytes must obey retirement too, not only the next syscall.
            @Override public synchronized int read()throws IOException{check();int value=super.read();check();return value;}
            @Override public synchronized int read(byte[] bytes,int offset,int count)throws IOException{check();int value=super.read(bytes,offset,count);check();return value;}
            @Override public void close()throws IOException{FdClient.this.close();}
        };
        private final OutputStream output=new OutputStream(){
            public void write(int value)throws IOException{write(new byte[]{(byte)value},0,1);}
            public void write(byte[] bytes,int offset,int count)throws IOException{
                bounds(bytes,offset,count);
                try(ParcelFileDescriptor pinned=operation()){
                  while(count>0){
                    check();if(outputEnded.get())throw new IOException("Accepted socket output ended");
                    try{
                        int sent=Os.write(pinned.getFileDescriptor(),bytes,offset,count);
                        if(sent<1)throw new IOException("Accepted socket write incomplete");offset+=sent;count-=sent;
                    }catch(ErrnoException failure){throw ioFailure(failure);}
                  }
                }
                check();
            }
            public void close()throws IOException{FdClient.this.close();}
        };
        public InputStream getInputStream()throws IOException{check();return input;}
        public OutputStream getOutputStream()throws IOException{check();return output;}
        public void shutdownOutput()throws IOException{
            synchronized(ownership){check();if(!outputEnded.compareAndSet(false,true))return;
            try{Os.shutdown(owner.getFileDescriptor(),OsConstants.SHUT_WR);}
            catch(ErrnoException failure){throw new IOException("Accepted socket half-close unavailable");}
            }
        }
        public void close()throws IOException{
            synchronized(ownership){if(!ended.compareAndSet(false,true))return;
            // Shutdown first so blocked read/write can exit before descriptor
            // disposal. Actual Android exit/FD-recycle barriers remain gates.
            try{Os.shutdown(owner.getFileDescriptor(),OsConstants.SHUT_RDWR);}catch(ErrnoException ignored){}
            owner.close();
            }
        }
        @Override public String toString(){return "AcceptedProxyClient(redacted)";}
    }
}
