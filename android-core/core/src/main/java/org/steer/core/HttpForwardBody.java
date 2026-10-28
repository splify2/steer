package org.steer.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** One authenticated HTTP request body only. Never copy a subsequent pipelined
 * request (and its Proxy-Authorization) into the first origin connection. */
public final class HttpForwardBody {
    public static final long MAX_BODY=1L<<30;
    private HttpForwardBody(){}
    public static void copy(ProxyHandshake.Request request,InputStream input,OutputStream output,
            AuthenticatedProxy.Cancellation cancellation,Runnable progress)throws IOException{
        if(request==null||request.protocol!=ProxyHandshake.Protocol.HTTP_FORWARD||input==null||output==null||cancellation==null||progress==null)
            throw new IllegalArgumentException("Owned single HTTP request required");
        byte[] block=new byte[16384];
        if(!request.chunked){fixed(input,output,request.bodyLength,block,cancellation,progress);return;}
        long total=0;
        for(int chunks=0;chunks<1000000;chunks++){
            check(cancellation);String line=line(input,1024);
            int extension=line.indexOf(';');String number=extension<0?line:line.substring(0,extension);
            if(!number.matches("[0-9a-fA-F]{1,8}"))throw new IOException("Invalid HTTP chunk");
            long length=Long.parseLong(number,16);
            if(length>MAX_BODY-total)throw new IOException("HTTP body limit");
            if(length==0){trailers(input,output,cancellation);progress.run();return;}
            total+=length;
            output.write((line+"\r\n").getBytes(StandardCharsets.US_ASCII));
            fixed(input,output,length,block,cancellation,progress);
            if(octet(input)!=13||octet(input)!=10)throw new IOException("Invalid chunk terminator");
            output.write(new byte[]{13,10});output.flush();progress.run();
        }
        throw new IOException("HTTP chunk count limit");
    }
    private static void fixed(InputStream input,OutputStream output,long length,byte[] block,
            AuthenticatedProxy.Cancellation cancellation,Runnable progress)throws IOException{
        if(length<0||length>MAX_BODY)throw new IOException("HTTP body limit");
        while(length>0){
            check(cancellation);int n=input.read(block,0,(int)Math.min(length,block.length));
            if(n<0)throw new EOFException("Short HTTP body");if(n==0)continue;
            output.write(block,0,n);output.flush();length-=n;progress.run();
        }
    }
    private static void trailers(InputStream input,OutputStream output,AuthenticatedProxy.Cancellation cancellation)throws IOException{
        ByteArrayOutputStream safe=new ByteArrayOutputStream();Set<String> seen=new HashSet<>();int budget=8192;
        for(int count=0;;count++){
            check(cancellation);String value=line(input,budget);budget-=value.length()+2;
            if(budget<0||count>64)throw new IOException("HTTP trailer limit");
            if(value.isEmpty())break;
            int colon=value.indexOf(':');
            if(colon<1||!value.substring(0,colon).matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+"))throw new IOException("Invalid HTTP trailer");
            String name=value.substring(0,colon).toLowerCase(Locale.ROOT);
            if(!seen.add(name))throw new IOException("Duplicate HTTP trailer");
            if(name.equals("proxy-authorization")||name.equals("proxy-authenticate"))continue;
            if(Arrays.asList("host","content-length","transfer-encoding","connection","proxy-connection","upgrade","trailer","authorization","te").contains(name))
                throw new IOException("Forbidden HTTP trailer");
            safe.write((value+"\r\n").getBytes(StandardCharsets.US_ASCII));
        }
        output.write("0\r\n".getBytes(StandardCharsets.US_ASCII));safe.writeTo(output);output.write(new byte[]{13,10});output.flush();
    }
    private static String line(InputStream input,int limit)throws IOException{
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        for(;;){
            int c=octet(input);if(c==13){if(octet(input)!=10)throw new IOException("Invalid HTTP line");return bytes.toString("US-ASCII");}
            if(c<32||c>126||bytes.size()>=limit)throw new IOException("Invalid/bounded HTTP line");bytes.write(c);
        }
    }
    private static int octet(InputStream input)throws IOException{int value=input.read();if(value<0)throw new EOFException("Short HTTP framing");return value;}
    private static void check(AuthenticatedProxy.Cancellation cancellation)throws IOException{if(cancellation.cancelled())throw new IOException("HTTP body cancelled");}
}
