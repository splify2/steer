package org.steer.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Bounded RFC1928 UDP wire codec only. No association, DNS, socket or native
 * capability. SOCKS FRAG is rejected (distinct from native IPv6 fragmentation).
 * Sender authorization/lifetime belong to the authenticated TCP association. */
public final class SocksUdpPacket {
    public static final int MAX_PACKET=65507;
    public static final class Packet {
        public final ProxyHandshake.Target target;
        private final byte[] payload;
        private Packet(ProxyHandshake.Target target,byte[] payload){this.target=target;this.payload=payload.clone();}
        public byte[] payload(){return payload.clone();}
        @Override public String toString(){return "SocksUdpPacket(redacted)";}
    }
    private SocksUdpPacket(){}
    public static Packet parse(byte[] input,int length)throws IOException{
        if(input==null||length<7||length>input.length||length>MAX_PACKET||input[0]!=0||input[1]!=0||input[2]!=0)
            throw new IOException("Invalid SOCKS datagram");
        int type=input[3]&255,at=4;byte[] numeric=null;String domain=null;
        if(type==1||type==4){
            int size=type==1?4:16;if(at+size+2>length)throw new IOException("Short SOCKS destination");
            numeric=Arrays.copyOfRange(input,at,at+size);at+=size;
        }else if(type==3){
            if(at>=length)throw new IOException("Short SOCKS name");int size=input[at++]&255;
            if(size==0||at+size+2>length)throw new IOException("Short SOCKS name");
            for(int i=at;i<at+size;i++)if((input[i]&255)<33||(input[i]&255)>126||input[i]==':')throw new IOException("Invalid SOCKS name");
            domain=new String(input,at,size,StandardCharsets.US_ASCII);at+=size;
        }else throw new IOException("Unsupported SOCKS address");
        int port=((input[at]&255)<<8)|(input[at+1]&255);at+=2;
        try{
            ProxyHandshake.Target target=domain==null?ProxyHandshake.Target.numeric(numeric,port):ProxyHandshake.Target.authority(domain+":"+port);
            return new Packet(target,Arrays.copyOfRange(input,at,length));
        }catch(IllegalArgumentException invalid){throw new IOException("Invalid SOCKS destination");}
    }
    public static byte[] encode(ProxyHandshake.Target source,byte[] payload)throws IOException{
        if(source==null||payload==null)throw new IOException("SOCKS datagram required");
        byte[] numeric=source.address();byte[] name=numeric==null?source.domain.getBytes(StandardCharsets.US_ASCII):null;
        int address=numeric==null?1+name.length:numeric.length,head=4+address+2;
        if((name!=null&&(name.length<1||name.length>255))||payload.length>MAX_PACKET-head)throw new IOException("SOCKS datagram limit");
        byte[] out=new byte[head+payload.length];int at=4;
        out[3]=(byte)(numeric==null?3:numeric.length==4?1:4);
        if(numeric==null){out[at++]=(byte)name.length;System.arraycopy(name,0,out,at,name.length);at+=name.length;}
        else{System.arraycopy(numeric,0,out,at,numeric.length);at+=numeric.length;}
        out[at++]=(byte)(source.port>>>8);out[at++]=(byte)source.port;
        System.arraycopy(payload,0,out,at,payload.length);return out;
    }
}
