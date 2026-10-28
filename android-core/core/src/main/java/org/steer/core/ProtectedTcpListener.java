package org.steer.core;

import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import java.io.FileDescriptor;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

/** SOURCE ONLY pre-bind listener ownership primitive, not proxy admission.
 * AndroidProxyListener supplies accepted-fd IO; actual flags remain OFF and
 * LAN/standalone remain refused; they are not prerequisites for local VPN proxy.
 * Uses public API29 socket flags, not hidden ServerSocket fd reflection.
 * https://developer.android.com/reference/android/system/Os
 * https://developer.android.com/reference/android/os/ParcelFileDescriptor
 */
public final class ProtectedTcpListener implements AutoCloseable {
    public interface Preparation {
        /** Borrowed fd valid ONLY during this synchronous worker-local call.
         * Host must protect AND bind the same underlying socket; a remote host
         * transfers its own duplicate PFD through Binder, never the integer.
         * False/stale generation/timeout is refusal, not optional protection. */
        boolean prepare(int borrowedDuplicateFd)throws IOException;
    }
    private final Object gate=new Object();
    private final ParcelFileDescriptor owner;
    private final AuthenticatedProxy.Cancellation cancellation;
    private final InetSocketAddress bound;
    private boolean closed;

    public ProtectedTcpListener(InetAddress address,int port,Preparation preparation,AuthenticatedProxy.Cancellation cancellation)throws IOException{
        if(address==null||!address.isLoopbackAddress()||port!=0&&(port<1024||port>65535)||preparation==null||cancellation==null)
            throw new IllegalArgumentException("Protected loopback listener inputs required");
        this.cancellation=cancellation;
        ParcelFileDescriptor pending=null;FileDescriptor raw=null;
        try{
            checkCancellation();
            raw=Os.socket(address.getAddress().length==4?OsConstants.AF_INET:OsConstants.AF_INET6,
                OsConstants.SOCK_STREAM|OsConstants.SOCK_CLOEXEC|OsConstants.SOCK_NONBLOCK,OsConstants.IPPROTO_TCP);
            pending=ParcelFileDescriptor.dup(raw);Os.close(raw);raw=null;
            // ACK before bind/listen: a bound ServerSocket converted afterward
            // is already too late. Duplicate shares the actual socket state.
            try(ParcelFileDescriptor borrowed=pending.dup()){
                if(!preparation.prepare(borrowed.getFd()))throw new IOException("Listener socket preparation refused");
            }
            checkCancellation();
            Os.bind(pending.getFileDescriptor(),address,port);
            checkCancellation();Os.listen(pending.getFileDescriptor(),16);
            InetSocketAddress endpoint=(InetSocketAddress)Os.getsockname(pending.getFileDescriptor());
            if(!endpoint.getAddress().equals(address)||endpoint.getPort()<1024||port!=0&&endpoint.getPort()!=port)
                throw new IOException("Protected listener endpoint mismatch");
            checkCancellation();bound=endpoint;owner=pending;pending=null;
        }catch(ErrnoException failure){throw new IOException("Protected listener unavailable");}
        finally{
            if(raw!=null)try{Os.close(raw);}catch(ErrnoException ignored){}
            if(pending!=null)try{pending.close();}catch(IOException ignored){}
        }
    }
    public InetSocketAddress bound(){return bound;}
    private void checkCancellation()throws IOException{
        if(cancellation.cancelled()||Thread.currentThread().isInterrupted())throw new IOException("Protected listener cancelled");
    }
    /** Caller owns the returned accepted fd and must close it on ALL paths.
     * No input/output/authentication occurs here. AndroidProxyListener owns the
     * accepted-fd IO adapter; AuthenticatedProxy owns credential negotiation.
     * A poll result alone never grants a client connection after owner close. */
    public ParcelFileDescriptor accept()throws IOException{
        for(;;){
            StructPollfd wait=new StructPollfd();
            synchronized(gate){checkCancellation();if(closed)throw new IOException("Protected listener closed");wait.fd=owner.getFileDescriptor();wait.events=(short)OsConstants.POLLIN;}
            try{
                if(Os.poll(new StructPollfd[]{wait},100)==0)continue;
                synchronized(gate){
                    checkCancellation();if(closed)throw new IOException("Protected listener closed");
                    FileDescriptor raw=null;ParcelFileDescriptor accepted=null;
                    try{
                        raw=Os.accept(owner.getFileDescriptor(),new InetSocketAddress(0));
                        accepted=ParcelFileDescriptor.dup(raw);Os.close(raw);raw=null;
                        InetSocketAddress local=(InetSocketAddress)Os.getsockname(accepted.getFileDescriptor());
                        InetSocketAddress peer=(InetSocketAddress)Os.getpeername(accepted.getFileDescriptor());
                        if(!bound.equals(local)||!peer.getAddress().isLoopbackAddress()||peer.getPort()<1)
                            throw new IOException("Protected listener peer rejected");
                        checkCancellation();ParcelFileDescriptor result=accepted;accepted=null;return result;
                    }finally{
                        if(raw!=null)try{Os.close(raw);}catch(ErrnoException ignored){}
                        if(accepted!=null)try{accepted.close();}catch(IOException ignored){}
                    }
                }
            }catch(ErrnoException failure){
                if(failure.errno==OsConstants.EAGAIN||failure.errno==OsConstants.EINTR)continue;
                throw new IOException("Protected listener accept unavailable");
            }
        }
    }
    @Override public void close(){synchronized(gate){
        if(closed)return;closed=true;
        try{Os.shutdown(owner.getFileDescriptor(),OsConstants.SHUT_RDWR);}catch(ErrnoException ignored){}
        try{owner.close();}catch(IOException ignored){}
    }}
    @Override public String toString(){return "ProtectedTcpListener(redacted)";}
}
