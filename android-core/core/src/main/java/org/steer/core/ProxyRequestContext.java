package org.steer.core;

import java.io.IOException;
import java.net.InetAddress;
import java.util.*;

/** SOURCE ONLY immutable proxy-request metadata model. Factory validation is
 * NOT evidence that the supplied UIDs came from Android: the owned caller must
 * obtain them freshly from BOTH actual observed sockets. No invented combined
 * kernel tuple: client/relay and requested destination may use different IP
 * families, ports and (SOCKS UDP) sockets. No credentials or network IO here. */
public final class ProxyRequestContext {
    private final FlowIdentity control,data;
    private final ProxyHandshake.Target requested;
    private final Set<String> packages;
    public final int uid,protocol,sourcePort,destinationPort;
    private ProxyRequestContext(FlowIdentity control,FlowIdentity data,int uid,Set<String> packages,ProxyHandshake.Target requested){
        this.control=control;this.data=data;this.uid=uid;this.packages=packages;this.requested=requested;
        protocol=data.protocol;sourcePort=data.sourcePort;destinationPort=requested.port;
    }
    public static ProxyRequestContext observed(FlowIdentity control,FlowIdentity data,int controlUid,int dataUid,
            Set<String> ownerPackages,ProxyHandshake.Target requested)throws IOException{
        if(control==null||data==null||requested==null||control.protocol!=6||controlUid<0||dataUid!=controlUid||
                ownerPackages==null||ownerPackages.isEmpty()||ownerPackages.size()>512)throw new IOException("Observed owned proxy request required");
        if(!Arrays.equals(control.source(),data.source())||!Arrays.equals(control.destination(),data.destination())||
                !InetAddress.getByAddress(control.source()).isLoopbackAddress()||!InetAddress.getByAddress(control.destination()).isLoopbackAddress())
            throw new IOException("Proxy control/client endpoints differ");
        if(data.protocol==6&&!Arrays.equals(control.encode(),data.encode()))throw new IOException("TCP request differs from authenticated control");
        Set<String> copy=new HashSet<>(ownerPackages);
        if(copy.isEmpty()||copy.size()>512)throw new IOException("Proxy package bound");
        for(String name:copy)if(name==null||name.length()>255||!name.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z0-9_]+)*"))throw new IOException("Invalid observed proxy identity");
        return new ProxyRequestContext(control,data,controlUid,Collections.unmodifiableSet(copy),requested);
    }
    public FlowIdentity control(){return control;}
    public FlowIdentity data(){return data;}
    public byte[] source(){return data.source();}
    public ProxyHandshake.Target requested(){return requested;}
    public Set<String> packages(){return packages;}
    public boolean sameRequest(ProxyHandshake.Target other){
        return other!=null&&requested.port==other.port&&Objects.equals(requested.domain,other.domain)&&Arrays.equals(requested.address(),other.address());
    }
    /** Bind a freshly verified request to the exact live alias mapping. A
     * numeric client may supply our issued alias OR the actual numeric target;
     * a domain request must retain its original normalized name. This method
     * does not prove ownership, mapping lifetime or registry admission. */
    public boolean matchesResolved(byte[] alias,String domain,byte[] real){
        if(alias==null||real==null||(real.length!=4&&real.length!=16)||alias.length!=real.length||
                Ipv6Routes.mappedIpv4(alias)||Ipv6Routes.mappedIpv4(real))return false;
        byte[] numeric=requested.address();
        if(numeric!=null)return Arrays.equals(numeric,alias)||Arrays.equals(numeric,real);
        try{return domain!=null&&requested.domain.equals(DomainNames.normalize(domain));}
        catch(RuntimeException invalid){return false;}
    }
    @Override public String toString(){return "ProxyRequestContext(redacted)";}
}
