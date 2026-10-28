package org.steer.core;
import java.util.*;

/** IPv4 prefix arithmetic without DNS. Used on API 29+, including before excludeRoute existed. */
public final class Ipv4Routes {
    private Ipv4Routes() {}
    public static final class Prefix {
        public final long network;
        public final int bits;
        public Prefix(long network,int bits) {
            if(bits<0||bits>32||network<0||network>0xffffffffL)throw new IllegalArgumentException("Invalid IPv4 prefix");
            this.bits=bits;this.network=network & mask(bits);
            if(this.network!=network)throw new IllegalArgumentException("IPv4 prefix has host bits");
        }
        public boolean contains(Prefix other) {return bits<=other.bits && (other.network & mask(bits))==network;}
        public String address() {return ((network>>>24)&255)+"."+((network>>>16)&255)+"."+((network>>>8)&255)+"."+(network&255);}
        @Override public String toString(){return address()+"/"+bits;}
    }
    private static long mask(int bits){return bits==0?0:(0xffffffffL << (32-bits))&0xffffffffL;}
    public static Prefix parse(String text) {
        String[] parts=text.split("/",-1);if(parts.length!=2)throw new IllegalArgumentException("CIDR required");
        String[] octets=parts[0].split("\\.",-1);if(octets.length!=4)throw new IllegalArgumentException("Numeric IPv4 required");
        long addr=0;
        for(String octet:octets) {
            if(!octet.matches("0|[1-9][0-9]{0,2}"))throw new IllegalArgumentException("Invalid IPv4 octet");
            int n=Integer.parseInt(octet);if(n>255)throw new IllegalArgumentException("Invalid IPv4 octet");addr=(addr<<8)|n;
        }
        if(!parts[1].matches("0|[1-9][0-9]?"))throw new IllegalArgumentException("Invalid prefix length");
        return new Prefix(addr,Integer.parseInt(parts[1]));
    }
    public static List<Prefix> tunnelRoutes(List<Prefix> direct) {
        if(direct.size()>128)throw new IllegalArgumentException("At most 128 direct prefixes");
        List<Prefix> result=new ArrayList<>();subtract(new Prefix(0,0),direct,result);return Collections.unmodifiableList(result);
    }
    private static void subtract(Prefix node,List<Prefix> direct,List<Prefix> result) {
        boolean split=false;
        for(Prefix e:direct) {if(e.contains(node))return;if(node.contains(e))split=true;}
        if(!split) {
            if(result.size()>=4096)throw new IllegalArgumentException("Too many Android routes");
            result.add(node);return;
        }
        int bits=node.bits+1;
        subtract(new Prefix(node.network,bits),direct,result);
        subtract(new Prefix(node.network+(1L<<(32-bits)),bits),direct,result);
    }
}
