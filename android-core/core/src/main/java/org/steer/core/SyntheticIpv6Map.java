package org.steer.core;

import java.util.HashMap;
import java.util.Map;

/** Bounded, process-owned DNS mapping preparation. No Android, sockets or persistence.
 * The future dual-stack owner must supply its own non-overlapping ULA /64.
 * Unknown/expired owned aliases NEVER become ordinary direct/proxy destinations.
 * The legacy IPv4 configuration never instantiates this class. */
public final class SyntheticIpv6Map implements AutoCloseable {
    public static final int PROXY=1,DIRECT=2,BLOCK=3;
    public enum Kind { OUTSIDE, RESOLVED, DENY }
    public static final class Decision {
        public final Kind kind;
        public final int action;
        public final String domain;
        private final byte[] real;
        private Decision(Kind kind,int action,byte[] real,String domain){this.kind=kind;this.action=action;this.real=real==null?null:real.clone();this.domain=domain;}
        public byte[] address(){return real==null?null:real.clone();}
        @Override public String toString(){return "Ipv6DnsDecision("+kind+")";}
    }
    private static final class Mapping {
        final byte[] fake,real;
        final int action;
        final long expires;
        final String domain;
        Mapping(byte[] fake,byte[] real,int action,long expires,String domain){this.fake=fake.clone();this.real=real.clone();this.action=action;this.expires=expires;this.domain=domain;}
    }
    private final Ipv6Routes.Prefix prefix;
    private final int capacity;
    private final Map<String,Mapping> names=new HashMap<>(),addresses=new HashMap<>();
    private long next=1;
    private boolean closed;
    public SyntheticIpv6Map(Ipv6Routes.Prefix prefix,int capacity){
        if(prefix==null||prefix.bits!=64||(prefix.addressBytes()[0]&0xfe)!=0xfc||DnsControlRoutes.reserved6(prefix.addressBytes())||capacity<1||capacity>32768)
            throw new IllegalArgumentException("Owned ULA /64 and bounded capacity required");
        this.prefix=new Ipv6Routes.Prefix(prefix.addressBytes(),64);this.capacity=capacity;
    }
    public boolean ownsNamespace(byte[] address){return address!=null&&address.length==16&&prefix.contains(new Ipv6Routes.Prefix(address,128));}
    private static String key(byte[] address){return new Ipv6Routes.Prefix(address,128).address();}
    public synchronized byte[] record(String domain,byte[] real,int action,int ttl,long now){
        String canonical=DomainNames.normalize(domain);return recordKey("dns/"+canonical,real,action,ttl,now,canonical);
    }
    public synchronized byte[] recordNumeric(byte[] real,int action,int ttl,long now){
        byte[] target=new Ipv6Routes.Prefix(real,128).addressBytes();
        return recordKey("ip/"+key(target),target,action,ttl,now,null);
    }
    private byte[] recordKey(String name,byte[] real,int action,int ttl,long now,String domain){
        if(closed)throw new IllegalStateException("IPv6 DNS owner closed");
        if(ttl<0||now<0||(action!=PROXY&&action!=DIRECT))
            throw new IllegalArgumentException("Invalid IPv6 DNS mapping state");
        byte[] target=new Ipv6Routes.Prefix(real,128).addressBytes();
        if(Ipv6Routes.mappedIpv4(target))throw new IllegalArgumentException("Mapped IPv4 target refused");
        if(DnsControlRoutes.reserved6(target))throw new IllegalArgumentException("DNS control target refused");
        if(prefix.contains(new Ipv6Routes.Prefix(target,128)))throw new IllegalArgumentException("Upstream returned owned synthetic IPv6 address");
        long lifetime=Math.max(2L,ttl)*1000L;
        long expires=Math.addExact(now,lifetime); // no silent wrap to a live/expired alias
        Mapping previous=names.get(name);
        // A DNS refresh must not redirect an already issued alias to another
        // address/action, nor revive an expired alias still cached by a client.
        boolean reuse=previous!=null&&now<previous.expires&&previous.action==action&&java.util.Arrays.equals(previous.real,target);
        byte[] fake;
        if(reuse){fake=previous.fake.clone();expires=Math.max(expires,previous.expires);}
        else{
            // Bound retained generations, not just distinct DNS names. Expired
            // entries/serials are never recycled during this owner lifetime.
            if(addresses.size()>=capacity)throw new IllegalStateException("IPv6 DNS mapping capacity reached");
            fake=prefix.addressBytes();long serial=next;
            for(int i=15;i>=8;i--){fake[i]=(byte)serial;serial>>>=8;}
        }
        Mapping replacement=new Mapping(fake,target,action,expires,domain);
        String alias=key(fake);
        names.put(name,replacement);addresses.put(alias,replacement);
        if(!reuse)next++;
        return fake.clone();
    }
    public synchronized Decision lookup(byte[] address,long now){
        if(now<0)throw new IllegalArgumentException("Monotonic timestamp required");
        byte[] copied=new Ipv6Routes.Prefix(address,128).addressBytes();
        if(closed)return new Decision(Kind.DENY,BLOCK,null,null);
        if(!prefix.contains(new Ipv6Routes.Prefix(copied,128)))return new Decision(Kind.OUTSIDE,0,copied,null);
        Mapping mapping=addresses.get(key(copied));
        if(mapping==null||now>=mapping.expires)return new Decision(Kind.DENY,BLOCK,null,null);
        return new Decision(Kind.RESOLVED,mapping.action,mapping.real,mapping.domain);
    }
    @Override public synchronized void close(){closed=true;names.clear();addresses.clear();}
}
