package org.steer.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Numeric IPv6 prefix arithmetic, without DNS or Android calls.
 * Preparation for the dual-stack port: does not enable IPv6 in the existing
 * IPv4-only native ABI or turn a BLOCK rule into a direct-route exclusion. */
public final class Ipv6Routes {
    public static boolean mappedIpv4(byte[] address){
        if(address==null||address.length!=16)return false;
        for(int i=0;i<10;i++)if(address[i]!=0)return false;
        return address[10]==(byte)255&&address[11]==(byte)255;
    }
    private Ipv6Routes() {}
    public static final class Prefix {
        private final byte[] network;
        public final int bits;
        public Prefix(byte[] address,int bits) {
            if(address==null||address.length!=16||bits<0||bits>128)
                throw new IllegalArgumentException("Invalid IPv6 prefix");
            this.network=address.clone();this.bits=bits;
            for(int bit=bits;bit<128;bit++)if((network[bit/8]&(1<<(7-bit%8)))!=0)
                throw new IllegalArgumentException("IPv6 prefix has host bits");
        }
        public byte[] addressBytes(){return network.clone();}
        public boolean contains(Prefix other) {
            if(other==null||bits>other.bits)return false;
            for(int bit=0;bit<bits;bit++)if(((network[bit/8]^other.network[bit/8])&(1<<(7-bit%8)))!=0)return false;
            return true;
        }
        public String address(){
            StringBuilder out=new StringBuilder();
            for(int i=0;i<8;i++){if(i!=0)out.append(':');out.append(Integer.toHexString(((network[2*i]&255)<<8)|(network[2*i+1]&255)));}
            return out.toString();
        }
        @Override public String toString(){return address()+"/"+bits;}
        @Override public boolean equals(Object value){return value instanceof Prefix&&bits==((Prefix)value).bits&&Arrays.equals(network,((Prefix)value).network);}
        @Override public int hashCode(){return 31*Arrays.hashCode(network)+bits;}
    }
    /** Deliberately reject zones, brackets, hostnames and embedded dotted IPv4.
     * No InetAddress.getByName fallback is allowed for a routing literal. */
    public static byte[] address(String text){
        if(text==null||text.length()<2||text.length()>39||!text.matches("[0-9A-Fa-f:]+")||text.contains(":::"))
            throw new IllegalArgumentException("Numeric IPv6 required");
        int compressed=text.indexOf("::");
        if(compressed!=text.lastIndexOf("::"))throw new IllegalArgumentException("Repeated IPv6 compression");
        String[] left,right;
        if(compressed>=0){
            String a=text.substring(0,compressed),b=text.substring(compressed+2);
            left=a.isEmpty()?new String[0]:a.split(":",-1);
            right=b.isEmpty()?new String[0]:b.split(":",-1);
            if(left.length+right.length>=8)throw new IllegalArgumentException("IPv6 compression must omit a group");
        }else{left=text.split(":",-1);right=new String[0];if(left.length!=8)throw new IllegalArgumentException("Eight IPv6 groups required");}
        byte[] result=new byte[16];
        for(int i=0;i<left.length;i++)group(result,i,left[i]);
        for(int i=0;i<right.length;i++)group(result,8-right.length+i,right[i]);
        return result;
    }
    private static void group(byte[] out,int index,String text){
        if(!text.matches("[0-9A-Fa-f]{1,4}"))throw new IllegalArgumentException("Invalid IPv6 group");
        int value=Integer.parseInt(text,16);out[2*index]=(byte)(value>>>8);out[2*index+1]=(byte)value;
    }
    public static Prefix parse(String text){
        if(text==null)throw new IllegalArgumentException("IPv6 CIDR required");
        String[] parts=text.split("/",-1);
        if(parts.length!=2||!parts[1].matches("0|[1-9][0-9]{0,2}"))throw new IllegalArgumentException("IPv6 CIDR required");
        return new Prefix(address(parts[0]),Integer.parseInt(parts[1]));
    }
    public static List<Prefix> tunnelRoutes(List<Prefix> direct){
        if(direct==null)throw new IllegalArgumentException("Direct IPv6 prefixes required");
        List<Prefix> snapshot=new ArrayList<>(direct),result=new ArrayList<>();
        if(snapshot.size()>128||snapshot.contains(null))throw new IllegalArgumentException("At most128 direct IPv6 prefixes");
        subtract(new Prefix(new byte[16],0),snapshot,result,new long[1]);
        return Collections.unmodifiableList(result);
    }
    private static void subtract(Prefix node,List<Prefix> direct,List<Prefix> result,long[] work){
        boolean split=false;
        for(Prefix item:direct){
            if(++work[0]>1048576)throw new IllegalArgumentException("IPv6 route projection too complex");
            if(item.contains(node))return;
            if(node.contains(item))split=true;
        }
        if(!split){if(result.size()>=4096)throw new IllegalArgumentException("Too many Android IPv6 routes");result.add(node);return;}
        if(node.bits==128)throw new IllegalStateException("Cannot subdivide an IPv6 host");
        int next=node.bits+1;
        subtract(new Prefix(node.network,next),direct,result,work);
        byte[] right=node.network.clone();right[node.bits/8]|=(byte)(1<<(7-node.bits%8));
        subtract(new Prefix(right,next),direct,result,work);
    }
}
