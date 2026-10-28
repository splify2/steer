package org.steer.core;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** One native generation. No early-result cache and no tuple reuse: a delayed
 * ACK for a retired socket cannot authorize a new socket with the same tuple.
 * Bounded to16live/32768lifetime registrations, then explicit refusal/restart.
 * This is an evidence sink, NOT proof that the native bridge is implemented. */
public final class ProxyFlowRegistry implements ProxyFlowReadiness,AutoCloseable {
    private final long generation;
    private final Map<String,Permit> active=new HashMap<>();
    private final Set<String> used=new HashSet<>();
    private volatile boolean closed;
    public ProxyFlowRegistry(long generation){
        if(generation<=0)throw new IllegalArgumentException("Positive native generation required");
        this.generation=generation;
    }
    private static String key(byte[] alias,int targetPort,int localPort)throws IOException{
        if(alias==null||(alias.length!=4&&alias.length!=16)||targetPort<1||targetPort>65535||localPort<1||localPort>65535)
            throw new IOException("Invalid proxy flow identity");
        StringBuilder value=new StringBuilder();value.append(alias.length).append('/');
        for(byte b:alias){value.append(Character.forDigit((b>>>4)&15,16));value.append(Character.forDigit(b&15,16));}
        return value.append('/').append(targetPort).append('/').append(localPort).toString();
    }
    @Override public synchronized Pending begin(byte[] alias,int targetPort,int localPort)throws IOException{
        String key=key(alias,targetPort,localPort);
        if(closed||active.size()>=16||used.size()>=32768||used.contains(key))throw new IOException("Proxy flow evidence unavailable");
        Permit permit=new Permit(key);used.add(key);active.put(key,permit);return permit;
    }
    /** Called ONLY by the corresponding native owner after actual upstream
     * admission; malformed/stale/unknown/duplicate events never create state. */
    public synchronized boolean report(long generation,byte[] alias,int targetPort,int localPort,boolean ready){
        if(closed||generation!=this.generation)return false;
        final String key;try{key=key(alias,targetPort,localPort);}catch(IOException invalid){return false;}
        Permit permit=active.get(key);return permit!=null&&permit.finish(ready?1:2);
    }
    boolean reportNative(byte[] alias,int targetPort,int localPort,boolean ready){
        return report(generation,alias,targetPort,localPort,ready);
    }
    private final class Permit implements Pending {
        final String key;final AtomicInteger result=new AtomicInteger();final CountDownLatch event=new CountDownLatch(1);
        volatile boolean retired;
        Permit(String key){this.key=key;}
        boolean finish(int state){if(!result.compareAndSet(0,state))return false;event.countDown();return true;}
        @Override public boolean awaitReady(long deadline,AuthenticatedProxy.Cancellation cancellation)throws IOException,InterruptedException{
            if(cancellation==null)throw new IOException("Cancellation required");
            for(;;){
                if(closed||retired||cancellation.cancelled()){close();return false;}
                int state=result.get();if(state!=0)return state==1;
                long remaining=deadline-System.nanoTime();if(remaining<=0){close();return false;}
                event.await(Math.min(remaining,TimeUnit.MILLISECONDS.toNanos(50)),TimeUnit.NANOSECONDS);
            }
        }
        @Override public void close(){
            synchronized(ProxyFlowRegistry.this){retired=true;finish(2);active.remove(key,this);}
        }
        @Override public String toString(){return "ProxyFlowPermit(redacted)";}
    }
    @Override public synchronized void close(){
        if(closed)return;closed=true;
        for(Permit permit:active.values())permit.finish(2);
        active.clear();used.clear();
    }
    @Override public String toString(){return "ProxyFlowRegistry(redacted)";}
}
