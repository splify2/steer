package org.steer.core;
import java.io.*;
import java.util.*;

/** Bounded DNS parser. Synthetic replies never claim DNSSEC authentication. */
public final class DnsWire {
    private DnsWire() {}
    /** Exact IN A/AAAA question for the owned resolver, never platform DNS. */
    public static byte[] query(String domain,int type,int id)throws IOException {
        if((type!=1&&type!=28)||id<0||id>65535)throw new IOException("Invalid DNS question");
        final String canonical;
        try{canonical=DomainNames.normalize(domain);}catch(RuntimeException invalid){throw new IOException("Invalid DNS name");}
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
        out.writeShort(id);out.writeShort(0x0100);out.writeShort(1);
        out.writeShort(0);out.writeShort(0);out.writeShort(0);
        for(String label:canonical.split("\\.")){
            byte[] text=label.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            out.writeByte(text.length);out.write(text);
        }
        out.writeByte(0);out.writeShort(type);out.writeShort(1);out.flush();return bytes.toByteArray();
    }
    public static int u16(byte[] p,int at) throws IOException {if(at<0||at+2>p.length)throw new IOException("Short DNS field");return ((p[at]&255)<<8)|(p[at+1]&255);}
    private static String name(byte[] p,int[] pos) throws IOException {
        int cursor=pos[0],jumps=0;boolean pointer=false;StringBuilder out=new StringBuilder();
        for(;;) {
            if(cursor>=p.length)throw new IOException("Short DNS name");int n=p[cursor++]&255;
            if(n==0){if(!pointer)pos[0]=cursor;break;}
            if((n&192)==192){if(cursor>=p.length||++jumps>32)throw new IOException("DNS pointer loop");int target=((n&63)<<8)|(p[cursor++]&255);if(!pointer)pos[0]=cursor;pointer=true;cursor=target;continue;}
            if((n&192)!=0||n>63||cursor+n>p.length)throw new IOException("Invalid DNS label");
            if(out.length()>0)out.append('.');for(int i=0;i<n;i++){int c=p[cursor++]&255;if(c<=32||c>=127||c=='.')throw new IOException("Invalid DNS name byte");out.append((char)c);}
            if(out.length()>253)throw new IOException("Long DNS name");
        }
        try{return DomainNames.normalize(out.toString());}catch(IllegalArgumentException e){throw new IOException("Invalid DNS name",e);}
    }
    public static final class Question {
        public final String name;public final int type,end;
        Question(String name,int type,int end){this.name=name;this.type=type;this.end=end;}
    }
    public static Question question(byte[] p,boolean response) throws IOException {
        if(p.length<12||u16(p,4)!=1||((p[2]&128)!=0)!=response||(p[2]&0x78)!=0)throw new IOException("Invalid DNS header");
        int[] at={12};String name=name(p,at);int type=u16(p,at[0]);if(u16(p,at[0]+2)!=1)throw new IOException("DNS class not IN");
        return new Question(name,type,at[0]+4);
    }
    public static byte[] reply(byte[] query,int rcode,Long ipv4,int ttl) throws IOException {
        byte[] address=null;
        if(ipv4!=null){
            if(ipv4<0||ipv4>0xffffffffL)throw new IOException("Invalid synthetic A address");
            address=new byte[]{(byte)(ipv4>>>24),(byte)(ipv4>>>16),(byte)(ipv4>>>8),ipv4.byteValue()};
        }
        return replyAddress(query,rcode,address,ttl,1);
    }
    /** Explicit opt-in DNS-only compatibility, never an automatic response to a
     * missing physical IPv6 route. null means continue the SAME configured DNS
     * plan/detour. It does not change packet routes or numeric IPv6 destinations. */
    public static byte[] ipv4OnlyReply(byte[] query,boolean enabled)throws IOException{
        if(!enabled)return null; // default path does not parse the same question twice
        Question q=question(query,false);
        return q.type==28?reply6(query,0,null,0):null;
    }
    /** Codec preparation only: the current IPv4-only TunnelDns does not emit AAAA. */
    public static byte[] reply6(byte[] query,int rcode,byte[] ipv6,int ttl)throws IOException{
        if(ipv6!=null&&ipv6.length!=16)throw new IOException("Invalid synthetic AAAA address");
        return replyAddress(query,rcode,ipv6==null?null:ipv6.clone(),ttl,28);
    }
    private static byte[] replyAddress(byte[] query,int rcode,byte[] address,int ttl,int type)throws IOException{
        Question q=question(query,false);ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
        if(address!=null&&(q.type!=type||rcode!=0||ttl<0))throw new IOException("Synthetic DNS family/status mismatch");
        out.writeShort(u16(query,0));out.writeShort(0x8080|((query[2]&1)<<8)|(rcode&15));out.writeShort(1);out.writeShort(address==null?0:1);out.writeInt(0);
        // Re-encode the question: never copy a pointer to data absent from the reply.
        for(String label:q.name.split("\\.")){out.writeByte(label.length());out.writeBytes(label);}out.writeByte(0);out.writeShort(q.type);out.writeShort(1);
        if(address!=null){out.writeShort(0xc00c);out.writeShort(type);out.writeShort(1);out.writeInt(ttl);out.writeShort(address.length);out.write(address);}
        return bytes.toByteArray();
    }
    public static final class Answer {public final long ipv4;public final int ttl,rcode;Answer(long ip,int ttl,int rcode){this.ipv4=ip;this.ttl=ttl;this.rcode=rcode;}}
    public static final class Answer6 {
        private final byte[] ipv6;
        public final int ttl,rcode;
        private Answer6(byte[] ip,int ttl,int rcode){this.ipv6=ip==null?null:ip.clone();this.ttl=ttl;this.rcode=rcode;}
        public byte[] address(){return ipv6==null?null:ipv6.clone();}
    }
    public static Answer6 answer6(byte[] query,byte[] response)throws IOException{
        if(query.length>65535||response.length>65535)throw new IOException("Oversized DNS packet");
        Question expected=question(query,false),q=question(response,true);
        if(expected.type!=28||q.type!=28||!expected.name.equals(q.name)||u16(query,0)!=u16(response,0)||(response[2]&2)!=0)
            throw new IOException("AAAA response mismatch/truncated");
        int rcode=response[3]&15;if(rcode!=0)return new Answer6(null,0,rcode);
        int count=u16(response,6);if(count>256)throw new IOException("Too many AAAA answers");
        Map<String,String> aliases=new HashMap<>();Map<String,byte[]> addresses=new HashMap<>();
        int ttl=60,at=q.end;
        for(int i=0;i<count;i++){
            int[] cursor={at};String owner=name(response,cursor);at=cursor[0];
            int type=u16(response,at),cls=u16(response,at+2);
            long seconds=((long)u16(response,at+4)<<16)|u16(response,at+6);
            int length=u16(response,at+8);at+=10;
            if(length>response.length-at)throw new IOException("Short AAAA RDATA");
            ttl=(int)Math.min(ttl,seconds);
            if(cls==1&&type==28){
                if(length!=16)throw new IOException("Invalid AAAA length");
                addresses.putIfAbsent(owner,Arrays.copyOfRange(response,at,at+16));
            }
            if(cls==1&&type==5){
                int[] pointer={at};String alias=name(response,pointer);
                if(pointer[0]!=at+length)throw new IOException("Invalid CNAME length");
                String previous=aliases.putIfAbsent(owner,alias);
                if(previous!=null&&!previous.equals(alias))throw new IOException("Conflicting CNAME aliases");
            }
            at+=length;
        }
        String canonical=q.name;Set<String> seen=new HashSet<>();
        while(aliases.containsKey(canonical)){
            if(!seen.add(canonical)||seen.size()>16)throw new IOException("AAAA CNAME loop");
            canonical=aliases.get(canonical);
        }
        return new Answer6(addresses.get(canonical),Math.max(0,ttl),0);
    }
    public static Answer answer(byte[] query,byte[] response) throws IOException {
        Question expected=question(query,false),q=question(response,true);
        if(!expected.name.equals(q.name)||q.type!=expected.type||u16(query,0)!=u16(response,0)||(response[2]&2)!=0)throw new IOException("DNS response mismatch/truncated");
        int rcode=response[3]&15;if(rcode!=0)return new Answer(0,0,rcode);
        int count=u16(response,6);if(count>256)throw new IOException("Too many DNS answers");
        Map<String,String> aliases=new HashMap<>();Map<String,Long> ips=new HashMap<>();int ttl=60;int at=q.end;
        for(int i=0;i<count;i++) {
            int[] cursor={at};String owner=name(response,cursor);at=cursor[0];int type=u16(response,at),cls=u16(response,at+2);long seconds=((long)u16(response,at+4)<<16)|u16(response,at+6);int len=u16(response,at+8);at+=10;
            if(at+len>response.length)throw new IOException("Short DNS RDATA");ttl=(int)Math.min(ttl,seconds);
            if(cls==1&&type==1){if(len!=4)throw new IOException("Invalid A length");long ip=0;for(int j=0;j<4;j++)ip=(ip<<8)|(response[at+j]&255);ips.putIfAbsent(owner,ip);}
            if(cls==1&&type==5){int[] ptr={at};String alias=name(response,ptr);if(ptr[0]!=at+len)throw new IOException("Invalid CNAME length");aliases.put(owner,alias);}
            at+=len;
        }
        String canonical=q.name;Set<String> seen=new HashSet<>();
        while(aliases.containsKey(canonical)){if(!seen.add(canonical)||seen.size()>16)throw new IOException("CNAME loop");canonical=aliases.get(canonical);}
        return new Answer(ips.getOrDefault(canonical,0L),Math.max(0,ttl),0);
    }
}
