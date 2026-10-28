package org.steer.core;

import org.json.*;
import java.net.URI;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

/** Immutable normalized per-rule upstream. Parses no system DNS, binds no
 * socket and never infers direct/ISP fallback when TLS bootstrap is missing. */
public final class DnsUpstreamPlan {
    public enum Kind { UDP, DOH, DOT }
    public final Kind kind;
    public final String url,host;
    public final int port;
    public final List<String> bootstrap;
    /** Numeric-only conversion; never getByName/system DNS. */
    public static byte[] numeric(String value){
        if(value==null)throw new IllegalArgumentException("Numeric DNS address required");
        String text=value.startsWith("[")&&value.endsWith("]")?value.substring(1,value.length()-1):value;
        if(!text.equals(value)&&!text.contains(":"))throw new IllegalArgumentException("Brackets require IPv6");
        if(text.contains(":")){
            byte[] bytes=Ipv6Routes.address(text);if(Ipv6Routes.mappedIpv4(bytes))throw new IllegalArgumentException("Mapped DNS address rejected");return bytes;
        }
        long ip=Ipv4Routes.parse(text+"/32").network;return new byte[]{(byte)(ip>>>24),(byte)(ip>>>16),(byte)(ip>>>8),(byte)ip};
    }
    public static String normalizedHost(String value){
        if(value==null)throw new IllegalArgumentException("DNS host required");
        if(value.contains(":")||value.matches("[0-9.]+")){
            try{return InetAddress.getByAddress(numeric(value)).getHostAddress();}catch(UnknownHostException impossible){throw new IllegalArgumentException("DNS numeric length rejected");}
        }
        return DomainNames.normalize(value);
    }
    public boolean usesIpv6(){for(String ip:bootstrap)if(ip.contains(":"))return true;return host!=null&&host.contains(":");}
    public DnsUpstreamPlan(JSONObject json)throws JSONException{
        Set<String> keys=new HashSet<>();for(Iterator<String> it=json.keys();it.hasNext();)keys.add(it.next());
        if(keys.equals(Collections.singleton("dns_ipv4"))||keys.equals(Collections.singleton("dns_ipv6"))){
            boolean v6=json.has("dns_ipv6");String value=json.getString(v6?"dns_ipv6":"dns_ipv4");
            if(numeric(value).length!=(v6?16:4))throw new IllegalArgumentException("Exact DNS address family required");
            String literal=normalizedHost(value);
            kind=Kind.UDP;url=null;host=null;port=53;bootstrap=Collections.singletonList(literal);return;
        }
        boolean doh=json.has("doh_url"),dot=json.has("dot_url");
        if(doh==dot)throw new IllegalArgumentException("One DNS transport required");
        String valueKey=doh?"doh_url":"dot_url",bootstrapKey=doh?"doh_bootstrap":"dot_bootstrap";
        if(!new HashSet<>(Arrays.asList(valueKey,bootstrapKey)).containsAll(keys))throw new IllegalArgumentException("Unknown DNS upstream option");
        URI uri=URI.create(json.getString(valueKey));String name=uri.getHost();
        if(!(doh?"https":"tls").equals(uri.getScheme())||name==null||uri.getRawUserInfo()!=null||uri.getRawFragment()!=null||uri.getRawQuery()!=null)
            throw new IllegalArgumentException("Authenticated TLS DNS URL required");
        int chosen=uri.getPort()==-1?(doh?443:853):uri.getPort();
        if(chosen<1||chosen>65535||chosen==53)throw new IllegalArgumentException("TLS DNS port rejected");
        if(!doh&&uri.getRawPath()!=null&&!uri.getRawPath().isEmpty()&&!uri.getRawPath().equals("/"))throw new IllegalArgumentException("DoT path rejected");
        if(doh&&(uri.getRawPath()==null||uri.getRawPath().isEmpty()||uri.getRawPath().equals("/")))throw new IllegalArgumentException("Explicit DoH path required");
        host=normalizedHost(name);kind=doh?Kind.DOH:Kind.DOT;url=uri.toASCIIString();port=chosen;
        List<String> pins=new ArrayList<>();
        if(json.has(bootstrapKey)){
            JSONArray values=json.getJSONArray(bootstrapKey);if(values.length()>8)throw new IllegalArgumentException("DNS bootstrap capacity");
            for(int i=0;i<values.length();i++){
                String raw=values.getString(i);numeric(raw);String ip=normalizedHost(raw);
                if(!pins.contains(ip))pins.add(ip);
            }
        }
        if(pins.isEmpty()&&(name.contains(":")||name.matches("[0-9.]+")))pins.add(normalizedHost(name));
        bootstrap=Collections.unmodifiableList(pins);
    }
    @Override public String toString(){return "DnsUpstreamPlan("+kind+")";}
}
