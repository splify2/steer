package org.steer.core;

import java.util.*;
import java.util.function.Predicate;

/** Process-owned per-rule DNS control endpoints, not ordinary destinations.
 * Registration pins real numeric IPv4/IPv6, transport and exact port before any VPN socket.
 * Unknown alias/wrong port/protocol/closed owner DENY; no rule/default fallback.
 * Codes4/5 mean proxy/direct DNS port53, exposed locally as5353 to avoid the
 * ordinary TUN port53 capture loop. Only the native owner rewrites that port. */
public final class DnsControlRoutes implements AutoCloseable {
    private static final long PREFIX=0x0a590400L,MASK=0xfffffc00L;
    private static final byte[] PREFIX6={(byte)0xfd,(byte)0xfe,(byte)0xdc,(byte)0xba,(byte)0x98,0x76,(byte)0xdd,0x53,0,0,0,0,0,0,0,0};
    public static final class Endpoint {
        private final byte[] address;
        public final int port;
        private Endpoint(long ip,int port){address=bytes(ip);this.port=port;}
        private Endpoint(byte[] ip,int port){address=ip.clone();this.port=port;}
        public byte[] address(){return address.clone();}
        @Override public String toString(){return "DnsControlEndpoint(redacted)";}
    }
    private static final class Entry {
        final Endpoint alias;final long real;final byte[] real6;final int port,action;final boolean dns53;
        Entry(Endpoint alias,long real,int port,int action,boolean dns53){this.alias=alias;this.real=real;this.real6=null;this.port=port;this.action=action;this.dns53=dns53;}
        Entry(Endpoint alias,byte[] real,int port,int action,boolean dns53){this.alias=alias;this.real=0;this.real6=real.clone();this.port=port;this.action=action;this.dns53=dns53;}
    }
    private final Map<String,Entry> names=new HashMap<>();
    private final Map<Long,Entry> addresses=new HashMap<>();
    private final Map<String,Entry> addresses6=new HashMap<>();
    private final boolean ipv6;
    private final Predicate<byte[]> blocked6;
    private boolean closed;
    public DnsControlRoutes(){this(false);}
    public DnsControlRoutes(boolean ipv6){this(ipv6,null);}
    public DnsControlRoutes(boolean ipv6,Predicate<byte[]> blocked6){this.ipv6=ipv6;this.blocked6=blocked6;}
    public static boolean reserved(long ip){return (ip&MASK)==PREFIX;}
    public static boolean reserved6(byte[] ip){
        if(ip==null||ip.length!=16)return false;
        for(int at=0;at<14;at++)if(ip[at]!=PREFIX6[at])return false;return true;
    }
    private static String key6(byte[] ip){return Base64.getEncoder().encodeToString(ip);}
    private static byte[] bytes(long ip){return new byte[]{(byte)(ip>>>24),(byte)(ip>>>16),(byte)(ip>>>8),(byte)ip};}
    public synchronized Endpoint register(String ipv4,int port,int action,boolean dns53){
        if(closed||port<1||port>65535||(action!=1&&action!=2)||(dns53&&port!=53)||(!dns53&&port==53))
            throw new IllegalArgumentException("Owned exact DNS endpoint required");
        if(ipv4!=null&&ipv4.contains(":")){
            if(!ipv6)throw new IllegalArgumentException("IPv6 DNS requires explicit full capture");
            byte[] ip=Ipv6Routes.address(ipv4);
            if(Ipv6Routes.mappedIpv4(ip))throw new IllegalArgumentException("Mapped DNS upstream rejected");
            boolean zero=true;for(byte value:ip)zero&=value==0;
            if(zero||(ip[0]&255)==255||(ip[0]&255)==254&&(ip[1]&192)==128||reserved6(ip)||blocked6!=null&&blocked6.test(ip.clone()))
                throw new IllegalArgumentException("Unicast nonscoped DNS upstream required");
            String real=key6(ip),key="6:"+real+":"+port+":"+action+":"+dns53;
            Entry entry=names.get(key);if(entry!=null)return entry.alias;
            if(names.size()>=512)throw new IllegalStateException("DNS control capacity");
            byte[] alias=PREFIX6.clone();int index=names.size()+1;alias[14]=(byte)(index>>>8);alias[15]=(byte)index;
            Endpoint endpoint=new Endpoint(alias,dns53?5353:port);
            entry=new Entry(endpoint,ip,port,action,dns53);names.put(key,entry);addresses6.put(key6(alias),entry);return endpoint;
        }
        Ipv4Routes.Prefix prefix=Ipv4Routes.parse(ipv4+"/32");long ip=prefix.network;
        if(ip==0||ip==0xffffffffL||(ip&0xf0000000L)==0xe0000000L)throw new IllegalArgumentException("Unicast DNS upstream required");
        if(reserved(ip)||(ip&0xffff0000L)==0xc6130000L||(ip&0xfffffff0L)==0x0a590000L)
            throw new IllegalArgumentException("Upstream returned internal DNS control address");
        String key=Long.toHexString(ip)+":"+port+":"+action+":"+dns53;
        Entry entry=names.get(key);if(entry!=null)return entry.alias;
        if(names.size()>=512)throw new IllegalStateException("DNS control capacity");
        long alias=PREFIX+names.size()+1;
        Endpoint endpoint=new Endpoint(alias,dns53?5353:port);
        entry=new Entry(endpoint,ip,port,action,dns53);names.put(key,entry);addresses.put(alias,entry);return endpoint;
    }
    /** Must be called only for reserved(ip). High word matches hostdial contract. */
    public synchronized long routeForUid(long ip,int port,int protocol,int kernelUid,int actualHostUid){
        if(actualHostUid<0||kernelUid!=actualHostUid)return 3L<<32;
        return route(ip,port,protocol);
    }
    public synchronized long route(long ip,int port,int protocol){
        if(!reserved(ip)||closed)return 3L<<32;
        Entry entry=addresses.get(ip);
        if(entry==null||port!=entry.alias.port||(protocol!=6&&!(entry.dns53&&protocol==17)))return 3L<<32;
        return ((long)(entry.dns53?entry.action+3:entry.action)<<32)|entry.real;
    }
    public synchronized byte[] route6ForUid(byte[] ip,int port,int protocol,int kernelUid,int actualHostUid){
        if(actualHostUid<0||kernelUid!=actualHostUid)return new byte[]{3};return route6(ip,port,protocol);
    }
    public synchronized byte[] route6(byte[] ip,int port,int protocol){
        if(closed||!ipv6||!reserved6(ip))return new byte[]{3};Entry entry=addresses6.get(key6(ip));
        if(entry==null||port!=entry.alias.port||(protocol!=6&&!(entry.dns53&&protocol==17)))return new byte[]{3};
        byte[] result=new byte[17];result[0]=(byte)(entry.dns53?entry.action+3:entry.action);System.arraycopy(entry.real6,0,result,1,16);return result;
    }
    @Override public synchronized void close(){closed=true;names.clear();addresses.clear();addresses6.clear();}
}
