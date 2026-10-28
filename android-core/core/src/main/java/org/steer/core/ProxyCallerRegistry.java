package org.steer.core;

import java.io.IOException;
import java.util.*;

/** Original authenticated TCP caller attribution, bound BEFORE an owned VPN
 * socket can send. Only the exact full tuple AND actual host kernel UID may
 * use a lease. Retired tuples never fall back to the proxy worker identity. */
public final class ProxyCallerRegistry implements AutoCloseable {
    private final int hostUid;
    private boolean closed;
    private final Map<String,Lease> active=new HashMap<>();
    private final Set<String> used=new HashSet<>();
    public ProxyCallerRegistry(int hostUid){if(hostUid<0)throw new IllegalArgumentException("Actual host UID required");this.hostUid=hostUid;}
    private static String key(FlowIdentity original){return Base64.getEncoder().encodeToString(original.encode());}
    public synchronized Lease begin(FlowIdentity original,Set<String> packages)throws IOException{
        return begin(original,packages,null,null);
    }
    /** Context must have been captured from real client sockets, not inferred
     * from this outgoing host socket. Port/protocol bind the request lease. */
    public synchronized Lease beginRequest(FlowIdentity outgoing,ProxyRequestContext request,AuthenticatedProxy.Cancellation scope)throws IOException{
        if(outgoing==null||request==null||scope==null||scope.cancelled()||outgoing.protocol!=request.protocol||outgoing.destinationPort!=request.destinationPort)
            throw new IOException("Proxy request/outgoing flow mismatch");
        return begin(outgoing,request.packages(),request,scope);
    }
    private Lease begin(FlowIdentity original,Set<String> packages,ProxyRequestContext request,AuthenticatedProxy.Cancellation scope)throws IOException{
        if(original==null||packages==null||packages.isEmpty()||packages.size()>512)throw new IOException("Original proxy caller required");
        Set<String> copy=new HashSet<>(packages);
        // Observed PackageManager identity, not the user-configured include
        // list. Framework's real single-component package "android" is valid.
        for(String value:copy)if(value==null||value.length()>255||!value.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z0-9_]+)*"))throw new IOException("Invalid original proxy packages");
        String key=key(original);
        if(closed||active.size()>=48||used.size()>=32768||used.contains(key))throw new IOException("Proxy caller scope unavailable");
        Lease lease=new Lease(key,Collections.unmodifiableSet(copy),request,scope);active.put(key,lease);used.add(key);return lease;
    }
    private Lease live(String key){
        Lease lease=active.get(key);
        // Once observed cancelled it is retired forever, even if a bad scope
        // later returns false. The used tuple cannot be rebound this generation.
        if(lease!=null&&lease.scope!=null&&lease.scope.cancelled()){active.remove(key,lease);return null;}
        return lease;
    }
    /** null means an ordinary non-proxy flow. A known but retired/mismatched
     * proxy tuple is an explicit error, NEVER permission to use worker UID. */
    public synchronized Set<String> identity(FlowIdentity original,int kernelUid)throws IOException{
        if(closed||original==null)throw new IOException("Proxy caller owner closed");
        String key=key(original);if(!used.contains(key))return null;
        Lease lease=live(key);
        if(kernelUid!=hostUid||lease==null)throw new IOException("Retired or foreign proxy tuple");
        return lease.packages;
    }
    /** null is an ordinary flow; known old/retired/foreign leases REFUSE rather
     * than manufacture request source/ports from outgoing kernel metadata. */
    public synchronized ProxyRequestContext request(FlowIdentity original,int kernelUid)throws IOException{
        Lease lease=requestLease(original,kernelUid);return lease==null?null:lease.request;
    }
    synchronized Lease requestLease(FlowIdentity original,int kernelUid)throws IOException{
        if(closed||original==null)throw new IOException("Proxy request owner closed");
        String key=key(original);if(!used.contains(key))return null;
        Lease lease=live(key);
        if(kernelUid!=hostUid||lease==null||lease.request==null)throw new IOException("Original proxy request unavailable");
        return lease;
    }
    public final class Lease implements AutoCloseable {
        private final String key;private final Set<String> packages;private final ProxyRequestContext request;
        private final AuthenticatedProxy.Cancellation scope;
        private Lease(String key,Set<String> packages,ProxyRequestContext request,AuthenticatedProxy.Cancellation scope){this.key=key;this.packages=packages;this.request=request;this.scope=scope;}
        ProxyRequestContext context(){return request;}
        AuthenticatedProxy.Cancellation scope(){return scope;}
        @Override public void close(){synchronized(ProxyCallerRegistry.this){active.remove(key,this);}}
        @Override public String toString(){return "ProxyCallerLease(redacted)";}
    }
    @Override public synchronized void close(){closed=true;active.clear();used.clear();}
    @Override public String toString(){return "ProxyCallerRegistry(redacted)";}
}
