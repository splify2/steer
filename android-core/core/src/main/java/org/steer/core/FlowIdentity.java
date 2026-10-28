package org.steer.core;

import java.util.Arrays;

/** ORIGINAL kernel socket tuple, never the routed real destination. Numeric
 * only: family, protocol,2-byte source/destination ports, then source+dest IP.
 * A native owner callback must not truncate IPv6 or substitute a proxy socket. */
public final class FlowIdentity {
    public final int family,protocol,sourcePort,destinationPort;
    private final byte[] source,destination;
    private FlowIdentity(int protocol,byte[] source,int sourcePort,byte[] destination,int destinationPort){
        if(source==null||destination==null||(source.length!=4&&source.length!=16)||source.length!=destination.length||
                (protocol!=6&&protocol!=17)||sourcePort<1||sourcePort>65535||destinationPort<1||destinationPort>65535||
                Ipv6Routes.mappedIpv4(source)||Ipv6Routes.mappedIpv4(destination))throw new IllegalArgumentException("Exact original TCP/UDP tuple required");
        family=source.length==4?4:6;this.protocol=protocol;this.sourcePort=sourcePort;this.destinationPort=destinationPort;
        this.source=source.clone();this.destination=destination.clone();
    }
    public byte[] source(){return source.clone();}
    public byte[] destination(){return destination.clone();}
    public static FlowIdentity of(int protocol,byte[] source,int sourcePort,byte[] destination,int destinationPort){
        return new FlowIdentity(protocol,source,sourcePort,destination,destinationPort);
    }
    public static FlowIdentity parse(byte[] encoded){
        if(encoded==null||(encoded.length!=14&&encoded.length!=38))throw new IllegalArgumentException("Bounded flow identity required");
        byte[] input=encoded.clone();int size=(input[0]&255)==4?4:(input[0]&255)==6?16:0;
        if(size==0||input.length!=6+2*size)throw new IllegalArgumentException("Flow family/size mismatch");
        return of(input[1]&255,Arrays.copyOfRange(input,6,6+size),((input[2]&255)<<8)|(input[3]&255),
            Arrays.copyOfRange(input,6+size,input.length),((input[4]&255)<<8)|(input[5]&255));
    }
    public byte[] encode(){
        byte[] out=new byte[6+source.length*2];out[0]=(byte)family;out[1]=(byte)protocol;
        out[2]=(byte)(sourcePort>>>8);out[3]=(byte)sourcePort;out[4]=(byte)(destinationPort>>>8);out[5]=(byte)destinationPort;
        System.arraycopy(source,0,out,6,source.length);System.arraycopy(destination,0,out,6+source.length,destination.length);return out;
    }
    @Override public String toString(){return "FlowIdentity(redacted)";}
}
