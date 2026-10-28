package org.steer.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/** Owned frontend IO boundary. Android protected descriptors must not be
 * converted through private Socket constructors/reflection. This interface
 * does not authorize a LAN listener or manufacture original-client ownership. */
public interface ProxyListener extends AutoCloseable {
    interface Factory { ProxyListener open()throws IOException; }
    interface Client extends AutoCloseable {
        InetAddress getInetAddress();
        int getPort();
        InetAddress getLocalAddress();
        int getLocalPort();
        void setTcpNoDelay(boolean enabled)throws IOException;
        void setSoTimeout(int millis)throws IOException;
        InputStream getInputStream()throws IOException;
        OutputStream getOutputStream()throws IOException;
        void shutdownOutput()throws IOException;
        @Override void close()throws IOException;
    }
    InetAddress getInetAddress();
    int getLocalPort();
    Client accept()throws IOException;
    @Override void close()throws IOException;

    /** Existing Java loopback implementation for the queued pure-JVM models.
     * No Android protection claim; real worker selects its own explicit factory. */
    static Factory loopback(InetAddress address,int port){
        if(address==null||!address.isLoopbackAddress()||port<0||port>65535)
            throw new IllegalArgumentException("Bounded loopback listener required");
        return ()->{
            ServerSocket socket=new ServerSocket();
            try{socket.bind(new InetSocketAddress(address,port),16);}
            catch(IOException|RuntimeException failure){socket.close();throw failure;}
            return new ProxyListener(){
                public InetAddress getInetAddress(){return socket.getInetAddress();}
                public int getLocalPort(){return socket.getLocalPort();}
                public Client accept()throws IOException{return wrap(socket.accept());}
                public void close()throws IOException{socket.close();}
                @Override public String toString(){return "LoopbackProxyListener(redacted)";}
            };
        };
    }
    static Client wrap(Socket socket){
        if(socket==null)throw new IllegalArgumentException("Owned accepted socket required");
        return new Client(){
            public InetAddress getInetAddress(){return socket.getInetAddress();}
            public int getPort(){return socket.getPort();}
            public InetAddress getLocalAddress(){return socket.getLocalAddress();}
            public int getLocalPort(){return socket.getLocalPort();}
            public void setTcpNoDelay(boolean enabled)throws IOException{socket.setTcpNoDelay(enabled);}
            public void setSoTimeout(int millis)throws IOException{socket.setSoTimeout(millis);}
            public InputStream getInputStream()throws IOException{return socket.getInputStream();}
            public OutputStream getOutputStream()throws IOException{return socket.getOutputStream();}
            public void shutdownOutput()throws IOException{socket.shutdownOutput();}
            public void close()throws IOException{socket.close();}
            @Override public String toString(){return "ProxyClient(redacted)";}
        };
    }
}
