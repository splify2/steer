package org.steer.core;

import org.json.*;
import java.io.IOException;
import java.util.*;

/** SOURCE ONLY full-tuple predicate candidate, NOT worker/host admission.
 * Destination Geo/address grouping stays in NativeAddressMatch. Source address,
 * source/destination port groups and network/package conditions are ANDed;
 * members of a port group (exact OR range) are ORed. Pinned host rule semantics.
 * No source address, port, protocol or Android identity is guessed from DNS.
 */
public final class NativeFlowMatch {
    private static final String[] ADDRESS={"domain","domain_suffix","domain_keyword","domain_regex","ip_cidr","rule_set"};
    private final Node root;
    private NativeFlowMatch(Node node){root=node;}
    public boolean requiresFlow(){return root.flow;}
    public boolean requiresOwner(){return root.owner;}
    @Override public String toString(){return "NativeFlowMatch(redacted)";}
    public static NativeFlowMatch compileText(String text,NativeAddressMatch.Sets resolver,SrsAddressSet.Budget budget)throws IOException {
        if(text==null||budget==null||text.length()>262144)throw new IOException("Native flow source bound");
        budget.claim(1024L+text.length()*8L);
        try{
            return new NativeFlowMatch(row(new JSONObject(text),resolver,budget,0,new int[]{0}));
        }catch(JSONException|IllegalArgumentException invalid){throw new IOException("Invalid native flow condition");}
    }
    /** ORIGINAL tuple and actual owner package union must come from the owned
     * kernel callback. realDestination is separately resolved DNS metadata, not
     * a replacement source/port/owner. Missing evidence is checked BEFORE any
     * logical/inverted predicate, so inversion cannot manufacture identity. */
    public boolean matches(String domain,byte[] realDestination,FlowIdentity original,Set<String> ownerPackages){
        if(realDestination!=null&&((realDestination.length!=4&&realDestination.length!=16)||Ipv6Routes.mappedIpv4(realDestination)))return false;
        if(root.flow&&(original==null||realDestination==null||original.family!=(realDestination.length==4?4:6)))return false;
        Set<String> packages=Collections.emptySet();
        if(root.owner){
            if(ownerPackages==null||ownerPackages.isEmpty()||ownerPackages.size()>512)return false;
            packages=new HashSet<>(ownerPackages);
            if(packages.isEmpty()||packages.size()>512)return false;
            for(String value:packages)if(!packageName(value))return false;
        }
        return root.matches(new Frame(domain,realDestination==null?null:realDestination.clone(),original,packages));
    }
    /** Capability-gated proxy entry; not a claim of runtime acceptance. Unlike a TUN packet,
     * a loopback IPv4 client may request an IPv6 destination. Request port and
     * network are not the relay listener/TCP control port or outgoing socket. */
    public boolean matchesProxy(String domain,byte[] realDestination,ProxyRequestContext request){
        if(request==null||realDestination==null||(realDestination.length!=4&&realDestination.length!=16)||Ipv6Routes.mappedIpv4(realDestination))return false;
        byte[] numeric=request.requested().address();if(numeric!=null&&numeric.length!=realDestination.length)return false;
        if(root.owner&&request.packages().isEmpty())return false;
        return root.matches(new Frame(domain,realDestination.clone(),request));
    }
    private static final class Frame {
        final String domain;final byte[] destination,source;final int protocol,sourcePort,destinationPort;final Set<String> packages;
        Frame(String name,byte[] target,FlowIdentity original,Set<String> owners){
            domain=name;destination=target;source=original==null?null:original.source();packages=owners;
            protocol=original==null?0:original.protocol;sourcePort=original==null?0:original.sourcePort;destinationPort=original==null?0:original.destinationPort;
        }
        Frame(String name,byte[] target,ProxyRequestContext request){
            domain=name;destination=target;source=request.source();packages=request.packages();
            protocol=request.protocol;sourcePort=request.sourcePort;destinationPort=request.destinationPort;
        }
    }
    private static final class Node {
        boolean invert,and,flow,owner;List<Node> children;
        SrsAddressSet destination,source;Ports sourcePorts,destinationPorts;int protocols;
        Set<String> packages=Collections.emptySet();
        boolean matches(Frame frame){
            boolean result;
            if(children!=null){
                result=and;
                for(Node child:children)if(child.matches(frame)!=and){result=!and;break;}
            }else{
                result=(destination==null||destination.matches(frame.domain,frame.destination))&&
                    (source==null||source.matches(null,frame.source))&&
                    (sourcePorts==null||sourcePorts.contains(frame.sourcePort))&&
                    (destinationPorts==null||destinationPorts.contains(frame.destinationPort))&&
                    (protocols==0||(protocols&(frame.protocol==6?1:frame.protocol==17?2:0))!=0)&&
                    (packages.isEmpty()||!Collections.disjoint(packages,frame.packages));
            }
            return result!=invert;
        }
    }
    private static boolean packageName(String text){return text!=null&&text.length()<=255&&text.matches("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z0-9_]+)*");}
    private static void fields(JSONObject value,String... allowed)throws IOException {
        Set<String> names=new HashSet<>(Arrays.asList(allowed));
        for(Iterator<String> it=value.keys();it.hasNext();)if(!names.contains(it.next()))throw new IOException("Unsupported native flow condition");
    }
    private static JSONArray list(Object raw,int limit)throws IOException,JSONException {
        JSONArray values=raw instanceof JSONArray?(JSONArray)raw:new JSONArray().put(raw);
        if(values.length()<1||values.length()>limit)throw new IOException("Native flow list bound");return values;
    }
    private static JSONArray strings(Object raw,int limit)throws IOException,JSONException {
        JSONArray values=list(raw,limit);for(int i=0;i<values.length();i++)if(!(values.get(i) instanceof String))throw new IOException("Native flow string list required");
        return values;
    }
    private static Node row(JSONObject value,NativeAddressMatch.Sets resolver,SrsAddressSet.Budget budget,int depth,int[] count)throws IOException,JSONException {
        if(depth>16||++count[0]>4096)throw new IOException("Native flow tree bound");budget.claim(256);
        Node node=new Node();
        if(value.has("invert")&&!(value.opt("invert") instanceof Boolean))throw new IOException("Native flow inversion type");
        node.invert=value.optBoolean("invert",false);
        if(value.has("type")&&!(value.opt("type") instanceof String))throw new IOException("Native flow type");
        String type=value.optString("type","default");
        if(type.equals("logical")){
            fields(value,"type","mode","rules","invert");Object mode=value.opt("mode");
            if(!"and".equals(mode)&&!"or".equals(mode))throw new IOException("Native flow logical mode");node.and="and".equals(mode);
            JSONArray rows=value.getJSONArray("rules");if(rows.length()<1||rows.length()>256)throw new IOException("Native flow logical child bound");
            budget.claim(rows.length()*8L);List<Node> children=new ArrayList<>(rows.length());
            for(int i=0;i<rows.length();i++){
                Node child=row(rows.getJSONObject(i),resolver,budget,depth+1,count);children.add(child);node.owner|=child.owner;node.flow|=child.flow;
            }
            node.children=Collections.unmodifiableList(children);return node;
        }
        if(!type.equals("default"))throw new IOException("Unsupported native flow type");
        fields(value,"type","invert","domain","domain_suffix","domain_keyword","domain_regex","ip_cidr","rule_set",
            "source_ip_cidr","source_port","source_port_range","port","port_range","network","package_name");
        JSONObject address=new JSONObject();for(String key:ADDRESS)if(value.has(key))address.put(key,value.get(key));
        if(address.length()>0)node.destination=NativeAddressMatch.compile(address,resolver,budget);
        if(value.has("source_ip_cidr")){
            JSONArray cidrs=strings(value.get("source_ip_cidr"),4096);
            node.source=SrsAddressSet.fromGeoJson(new JSONObject().put("version",3).put("rules",new JSONArray().put(new JSONObject().put("ip_cidr",cidrs))),budget);
        }
        node.sourcePorts=ports(value,"source_port",budget);node.destinationPorts=ports(value,"port",budget);
        if(value.has("network")){
            JSONArray networks=strings(value.get("network"),2);
            for(int i=0;i<networks.length();i++){
                String network=networks.getString(i);int bit=network.equals("tcp")?1:network.equals("udp")?2:0;
                if(bit==0||(node.protocols&bit)!=0)throw new IOException("Unsupported/duplicate native network");node.protocols|=bit;
            }
        }
        if(value.has("package_name")){
            JSONArray names=strings(value.get("package_name"),512);Set<String> packages=new HashSet<>();budget.claim(names.length()*320L);
            for(int i=0;i<names.length();i++){
                String name=names.getString(i);if(!packageName(name)||!packages.add(name))throw new IOException("Invalid/duplicate native package");
            }
            node.packages=Collections.unmodifiableSet(packages);node.owner=true;
        }
        node.flow=node.owner||node.source!=null||node.sourcePorts!=null||node.destinationPorts!=null||node.protocols!=0;
        if(node.destination==null&&!node.flow)throw new IOException("Empty native flow condition");return node;
    }
    private static int port(Object value)throws IOException {
        if(!(value instanceof Integer||value instanceof Long)||((Number)value).longValue()<0||((Number)value).longValue()>65535)throw new IOException("Native port bound");
        return ((Number)value).intValue();
    }
    private static int endpoint(String value,int absent)throws IOException {
        if(value.isEmpty())return absent;
        if(value.length()>5||!value.matches("[0-9]+"))throw new IOException("Native port range syntax");
        return port(Integer.valueOf(value));
    }
    private static Ports ports(JSONObject row,String key,SrsAddressSet.Budget budget)throws IOException,JSONException {
        if(!row.has(key)&&!row.has(key+"_range"))return null;
        List<int[]> values=new ArrayList<>();
        if(row.has(key)){
            JSONArray exact=list(row.get(key),1024);budget.claim(exact.length()*32L);
            for(int i=0;i<exact.length();i++){int port=port(exact.get(i));values.add(new int[]{port,port});}
        }
        if(row.has(key+"_range")){
            JSONArray ranges=strings(row.get(key+"_range"),1024);budget.claim(ranges.length()*32L);
            for(int i=0;i<ranges.length();i++){
                String range=ranges.getString(i);int colon=range.indexOf(':');
                if(range.length()>11||colon<0||range.indexOf(':',colon+1)>=0)throw new IOException("Native port range syntax");
                int begin=endpoint(range.substring(0,colon),0),end=endpoint(range.substring(colon+1),65535);
                // The pinned host accepts reversed endpoints as an empty set.
                // Preserve that, rather than reverse/expand an imported range.
                if(begin<=end)values.add(new int[]{begin,end});
            }
        }
        values.sort((a,b)->Integer.compare(a[0],b[0]));List<int[]> merged=new ArrayList<>();budget.claim(values.size()*16L+64);
        for(int[] range:values){
            if(merged.isEmpty()||range[0]>merged.get(merged.size()-1)[1]+1)merged.add(range);
            else merged.get(merged.size()-1)[1]=Math.max(merged.get(merged.size()-1)[1],range[1]);
        }
        return new Ports(merged);
    }
    private static final class Ports {
        final int[] starts,ends;
        Ports(List<int[]> ranges){starts=new int[ranges.size()];ends=new int[ranges.size()];for(int i=0;i<starts.length;i++){starts[i]=ranges.get(i)[0];ends[i]=ranges.get(i)[1];}}
        boolean contains(int port){
            int lo=0,hi=starts.length-1;while(lo<=hi){int mid=(lo+hi)>>>1;if(port<starts[mid])hi=mid-1;else if(port>ends[mid])lo=mid+1;else return true;}return false;
        }
    }
}
