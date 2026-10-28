package org.steer.core;

import java.io.IOException;
import java.util.*;

/** Per-authenticated-control lifetime fence. Every observation still comes
 * from Android; this is NOT a UID cache or an alternative owner lookup. A UID
 * or shared-UID package-union change retires the identity, never rebinds it. */
public final class ProxyClientIdentity implements AutoCloseable {
    private int uid=-1;private boolean closed;
    private Set<String> packages;
    public synchronized void verify(int observedUid,Set<String> observedPackages)throws IOException{
        if(closed||observedUid<0||observedPackages==null||observedPackages.isEmpty()||observedPackages.size()>512)
            throw new IOException("Authenticated client identity unavailable");
        Set<String> copy=new HashSet<>(observedPackages);
        if(copy.isEmpty()||copy.size()>512)throw new IOException("Authenticated client package bound");
        for(String name:copy)if(name==null||name.length()>255||!name.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z0-9_]+)*"))throw new IOException("Invalid authenticated client packages");
        if(uid<0){uid=observedUid;packages=Collections.unmodifiableSet(copy);return;}
        if(uid!=observedUid||!packages.equals(copy)){closed=true;throw new IOException("Authenticated client identity changed");}
    }
    @Override public synchronized void close(){closed=true;packages=null;}
    public synchronized boolean retired(){return closed;}
    @Override public String toString(){return "ProxyClientIdentity(redacted)";}
}
