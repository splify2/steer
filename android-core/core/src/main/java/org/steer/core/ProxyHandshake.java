package org.steer.core;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.Set;
import java.net.URI;

/** Authenticated HTTP forwarding/CONNECT and SOCKS handshake, not a VPN.
 * Performs no DNS, socket creation, routing or native calls. The eventual owner
 * must impose a handshake deadline, dial through its protected route policy,
 * and send success only after that dial succeeds. Reads never consume payload.
 * HTTP absolute-form forwarding is one request per connection (no pipelining
 * credential leakage). SOCKS UDP requires an explicitly supplied owner; BIND
 * and HTTP Upgrade are unsupported.
 * Basic/RFC1929 credentials are plaintext on the local wire: do not expose this
 * preparation on LAN or advertise it as a TLS/authenticated encryption layer. */
public final class ProxyHandshake {
    private ProxyHandshake() {}
    private static final int MAX_HEADER = 8192, MAX_LINES = 64;
    public enum Protocol { HTTP_CONNECT, HTTP_FORWARD, SOCKS5_CONNECT, SOCKS5_UDP_ASSOCIATE }

    /** Client UDP endpoint from RFC1928. Zero address/port means not yet known;
     * this is NOT a destination and cannot be passed to the stream dialer. */
    public static final class UdpEndpoint {
        private final byte[] address;
        public final int port;
        private UdpEndpoint(byte[] address,int port){this.address=address.clone();this.port=port;}
        public byte[] address(){return address.clone();}
    }

    public static final class Credentials implements AutoCloseable {
        private final byte[] user, password;
        private boolean closed;
        public Credentials(byte[] user, byte[] password) {
            if (user == null || password == null || user.length < 1 || user.length > 255 ||
                    password.length < 1 || password.length > 255)
                throw new IllegalArgumentException("Bounded nonempty proxy credentials required");
            for (byte c : user) if (c == ':' || c == 0 || c == '\r' || c == '\n')
                throw new IllegalArgumentException("Invalid proxy username");
            for (byte c : password) if (c == 0 || c == '\r' || c == '\n')
                throw new IllegalArgumentException("Invalid proxy password");
            this.user = user.clone(); this.password = password.clone();
        }
        private synchronized boolean matches(byte[] u, byte[] p) {
            // No early return on an incorrect username/password byte.
            int difference = closed ? 1 : 0;
            difference |= user.length ^ u.length;
            difference |= password.length ^ p.length;
            for (int i = 0; i < 255; i++) {
                difference |= (i < user.length ? user[i] & 255 : 0) ^ (i < u.length ? u[i] & 255 : 0);
                difference |= (i < password.length ? password[i] & 255 : 0) ^ (i < p.length ? p[i] & 255 : 0);
            }
            return difference == 0;
        }
        private boolean basic(String value) {
            if (value == null || value.length() > 700 || value.length() < 10 ||
                    !value.regionMatches(true, 0, "Basic ", 0, 6)) return false;
            String encoded = value.substring(6);
            if ((encoded.length() & 3) != 0 || !encoded.matches("[A-Za-z0-9+/]+={0,2}")) return false;
            byte[] pair = null, u = null, p = null;
            try {
                pair = Base64.getDecoder().decode(encoded);
                if (!Base64.getEncoder().encodeToString(pair).equals(encoded)) return false;
                int colon = -1;
                for (int i = 0; i < pair.length; i++) if (pair[i] == ':') { colon = i; break; }
                if (colon < 1 || colon > 255 || pair.length - colon - 1 < 1 || pair.length - colon - 1 > 255) return false;
                u = Arrays.copyOfRange(pair, 0, colon); p = Arrays.copyOfRange(pair, colon + 1, pair.length);
                return matches(u, p);
            } catch (IllegalArgumentException invalid) { return false; }
            finally { wipe(pair); wipe(u); wipe(p); }
        }
        @Override public synchronized void close() { closed = true; wipe(user); wipe(password); }
        @Override public String toString() { return "ProxyCredentials(redacted)"; }
    }

    /** Retains a domain without resolving it; the route owner chooses DNS. */
    public static final class Target {
        public final String domain;
        public final int port;
        private final byte[] address;
        private Target(String domain, byte[] address, int port) {
            this(domain,address,port,false);
        }
        private Target(String domain,byte[] address,int port,boolean unspecifiedBound) {
            if ((port < 1 || port > 65535)&&!(unspecifiedBound&&port==0&&domain==null&&Arrays.equals(address,new byte[4])))
                throw new IllegalArgumentException("Invalid proxy port");
            this.domain = domain; this.address = address == null ? null : address.clone(); this.port = port;
        }
        /** RFC1928 unknown BND endpoint. Never use this as a requested target
         * or pretend a private UNIX relay has a real Internet socket address. */
        public static Target unspecifiedBound(){return new Target(null,new byte[4],0,true);}
        public byte[] address() { return address == null ? null : address.clone(); }
        public static Target numeric(byte[] bytes, int port) {
            if (bytes == null || (bytes.length != 4 && bytes.length != 16))
                throw new IllegalArgumentException("Numeric proxy address required");
            if (bytes.length == 16) {
                boolean mapped = bytes[10] == (byte)255 && bytes[11] == (byte)255;
                for (int i = 0; i < 10; i++) mapped &= bytes[i] == 0;
                if (mapped) throw new IllegalArgumentException("Mapped IPv4 proxy address not supported");
            }
            return new Target(null, bytes, port);
        }
        private static Target host(String text, int port) {
            if (text.isEmpty() || text.length() > 253) throw new IllegalArgumentException("Invalid proxy host");
            if (text.indexOf(':') >= 0) return numeric(Ipv6Routes.address(text), port);
            if (text.matches("[0-9.]+")) {
                String[] parts = text.split("\\.", -1);
                if (parts.length != 4) throw new IllegalArgumentException("IPv4 shorthand not supported");
                byte[] bytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    if (!parts[i].matches("0|[1-9][0-9]{0,2}")) throw new IllegalArgumentException("Invalid IPv4 component");
                    int number = Integer.parseInt(parts[i]);
                    if (number > 255) throw new IllegalArgumentException("Invalid IPv4 component");
                    bytes[i] = (byte) number;
                }
                return numeric(bytes, port);
            }
            // Do not let a later platform resolver reinterpret legacy hex/octal
            // address spellings as a route-policy-approved hostname.
            if (text.matches("(?i)(?:0x[0-9a-f]+|[0-9]+)(?:\\.(?:0x[0-9a-f]+|[0-9]+))*"))
                throw new IllegalArgumentException("Legacy numeric proxy address not supported");
            return new Target(DomainNames.normalize(text), null, port);
        }
        public static Target authority(String text) {
            if (text == null || text.length() > 300) throw new IllegalArgumentException("Bounded authority required");
            String host, port;
            if (text.startsWith("[")) {
                int close = text.indexOf(']');
                if (close < 2 || close + 2 >= text.length() || text.charAt(close + 1) != ':')
                    throw new IllegalArgumentException("Bracketed IPv6 authority required");
                host = text.substring(1, close); port = text.substring(close + 2);
                if (host.indexOf(':') < 0) throw new IllegalArgumentException("Only IPv6 may use brackets");
            } else {
                int colon = text.indexOf(':');
                if (colon < 1 || colon != text.lastIndexOf(':')) throw new IllegalArgumentException("Explicit proxy port required");
                host = text.substring(0, colon); port = text.substring(colon + 1);
            }
            if (!port.matches("[1-9][0-9]{0,4}")) throw new IllegalArgumentException("Invalid proxy port");
            return host(host, Integer.parseInt(port));
        }
        private boolean same(Target other) {
            return port == other.port && (domain == null ? other.domain == null && Arrays.equals(address, other.address) : domain.equals(other.domain));
        }
        @Override public String toString() { return "ProxyTarget(redacted)"; }
    }

    public static final class Request {
        public final Protocol protocol;
        public final Target target;
        private final byte[] forwardHead;
        public final long bodyLength;
        public final boolean chunked;
        public final UdpEndpoint udpEndpoint;
        private Request(Protocol protocol, Target target) { this(protocol,target,null,0,false); }
        private Request(Protocol protocol,Target target,byte[] head,long length,boolean chunked){
            this(protocol,target,head,length,chunked,null);
        }
        private Request(Protocol protocol,Target target,byte[] head,long length,boolean chunked,UdpEndpoint endpoint){
            this.protocol=protocol;this.target=target;this.forwardHead=head==null?null:head.clone();this.bodyLength=length;this.chunked=chunked;this.udpEndpoint=endpoint;
        }
        public byte[] forwardedHead(){return forwardHead==null?null:forwardHead.clone();}
        /** Stream bind is from the actual protected dial. For UDP ASSOCIATE
         * it is the actual owned relay bind, NOT a remote delivery proof. */
        public void connected(OutputStream out, Target bound) throws IOException {
            if (bound == null || bound.address == null) throw new IllegalArgumentException("Actual numeric bind endpoint required");
            if (protocol == Protocol.HTTP_CONNECT) httpStatus(out, "200 Connection Established", "");
            else if(protocol==Protocol.SOCKS5_CONNECT||protocol==Protocol.SOCKS5_UDP_ASSOCIATE) {
                out.write(new byte[]{5, 0, 0, (byte)(bound.address.length == 4 ? 1 : 4)});
                out.write(bound.address); out.write(bound.port >>> 8); out.write(bound.port); out.flush();
            }
        }
        public void failed(OutputStream out) throws IOException {
            if (protocol != Protocol.SOCKS5_CONNECT&&protocol!=Protocol.SOCKS5_UDP_ASSOCIATE) httpStatus(out, "502 Bad Gateway", "");
            else socksFailure(out, 1);
        }
    }

    /** Null means refused and caller MUST close. IOException also requires close.
     * An authenticated request is NOT proof that any dial/relay has happened. */
    public static Request read(InputStream in, OutputStream out, Credentials credentials) throws IOException {
        return read(in,out,credentials,false);
    }
    public static Request read(InputStream in, OutputStream out, Credentials credentials,boolean allowUdp) throws IOException {
        if (in == null || out == null || credentials == null) throw new IllegalArgumentException("Owned handshake state required");
        int first = octet(in);
        return first == 5 ? socks(in, out, credentials,allowUdp) : http(in, out, credentials, first);
    }
    private static Request socks(InputStream in, OutputStream out, Credentials credentials,boolean allowUdp) throws IOException {
        int count = octet(in); boolean auth = false;
        for (int i = 0; i < count; i++) auth |= octet(in) == 2;
        out.write(new byte[]{5, (byte)(auth ? 2 : 255)}); out.flush();
        if (!auth) return null; // never downgrade to the offered no-auth method
        byte[] user = null, password = null;
        boolean accepted;
        try {
            if (octet(in) != 1) { out.write(new byte[]{1, 1}); out.flush(); return null; }
            user = bytes(in, octet(in)); password = bytes(in, octet(in));
            accepted = credentials.matches(user, password);
        } finally { wipe(user); wipe(password); }
        out.write(new byte[]{1, (byte)(accepted ? 0 : 1)}); out.flush();
        if (!accepted) return null;
        int version = octet(in), command = octet(in), reserved = octet(in), type = octet(in);
        if (version != 5 || reserved != 0) { socksFailure(out, 1); return null; }
        if (command != 1 && !(command==3&&allowUdp)) { socksFailure(out, 7); return null; }
        try {
            byte[] numeric = null; String domain = null;
            if (type == 1) numeric = bytes(in, 4);
            else if (type == 4) numeric = bytes(in, 16);
            else if (type == 3) {
                byte[] raw = bytes(in, octet(in));
                for (byte c : raw) if ((c & 255) < 33 || (c & 255) > 126) throw new IllegalArgumentException("ASCII proxy hostname required");
                domain = new String(raw, StandardCharsets.US_ASCII);
                // RFC1928 domain form may contain an IPv4 spelling, not IPv6 authority syntax.
                if (domain.indexOf(':') >= 0) throw new IllegalArgumentException("Numeric IPv6 address type required");
            } else { socksFailure(out, 8); return null; }
            int port = (octet(in) << 8) | octet(in);
            if(command==3){
                if(numeric==null)throw new IllegalArgumentException("Numeric UDP client endpoint required");
                // Reuse the mapped-family check without interpreting port0 as
                // a routable target. The association validates peer identity.
                Target.numeric(numeric,Math.max(1,port));
                return new Request(Protocol.SOCKS5_UDP_ASSOCIATE,null,null,0,false,new UdpEndpoint(numeric,port));
            }
            Target target = domain == null ? Target.numeric(numeric, port) : Target.host(domain, port);
            return new Request(Protocol.SOCKS5_CONNECT, target);
        } catch (IllegalArgumentException malformed) { socksFailure(out, 8); return null; }
    }
    private static Request http(InputStream in, OutputStream out, Credentials credentials, int first) throws IOException {
        try {
            int[] budget = {MAX_HEADER};
            String line = line(in, first, budget);
            String[] start = line.split(" ", -1);
            if(start.length!=3||!start[2].equals("HTTP/1.1")||!start[0].matches("CONNECT|GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH"))
                throw new IllegalArgumentException("Supported HTTP/1.1 method required");
            boolean connect=start[0].equals("CONNECT");
            URI absolute=connect?null:URI.create(start[1]);
            if(!connect&&(!"http".equalsIgnoreCase(absolute.getScheme())||absolute.getRawAuthority()==null||absolute.getRawUserInfo()!=null||absolute.getRawFragment()!=null))
                throw new IllegalArgumentException("HTTP absolute target required");
            Target target=connect?Target.authority(start[1]):httpAuthority(absolute.getRawAuthority());
            Map<String, String> headers = new LinkedHashMap<>();
            for (int n = 0;; n++) {
                String header = line(in, -1, budget);
                if (header.isEmpty()) break;
                if (n >= MAX_LINES) throw new IllegalArgumentException("Too many proxy headers");
                int colon = header.indexOf(':');
                if (colon < 1 || !header.substring(0, colon).matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+"))
                    throw new IllegalArgumentException("Invalid proxy header");
                String key = header.substring(0, colon).toLowerCase(Locale.ROOT);
                if (headers.put(key, header.substring(colon + 1).trim()) != null)
                    throw new IllegalArgumentException("Duplicate proxy header");
            }
            String host=headers.get("host");
            if(host==null||!target.same(connect?Target.authority(host):httpAuthority(host)))throw new IllegalArgumentException("HTTP Host mismatch");
            if (!credentials.basic(headers.get("proxy-authorization"))) {
                httpStatus(out, "407 Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"local\", charset=\"UTF-8\"\r\n");
                return null;
            }
            if(connect && (headers.containsKey("transfer-encoding") ||
                    (headers.containsKey("content-length") && !headers.get("content-length").equals("0"))))
                throw new IllegalArgumentException("CONNECT request body not supported");
            if(connect)return new Request(Protocol.HTTP_CONNECT,target);
            if(headers.containsKey("upgrade"))throw new IllegalArgumentException("HTTP Upgrade unsupported");
            boolean chunked=headers.containsKey("transfer-encoding");
            if(chunked&&(!headers.get("transfer-encoding").equalsIgnoreCase("chunked")||headers.containsKey("content-length")))
                throw new IllegalArgumentException("Ambiguous HTTP body");
            long length=0;
            if(headers.containsKey("content-length")){
                String value=headers.get("content-length");
                if(!value.matches("0|[1-9][0-9]{0,10}"))throw new IllegalArgumentException("Invalid body length");
                length=Long.parseLong(value);if(length>HttpForwardBody.MAX_BODY)throw new IllegalArgumentException("HTTP body too large");
            }
            Set<String> hop=new HashSet<>(Arrays.asList("connection","proxy-connection","proxy-authorization","proxy-authenticate","keep-alive","te","trailer","upgrade"));
            if(headers.containsKey("connection"))for(String item:headers.get("connection").split(",",-1)){
                String token=item.trim().toLowerCase(Locale.ROOT);
                if(!token.matches("[!#$%&'*+.^_`|~0-9a-z-]+")||Arrays.asList("host","content-length","transfer-encoding","upgrade").contains(token))
                    throw new IllegalArgumentException("Unsafe hop header");
                hop.add(token);
            }
            String path=absolute.getRawPath();if(path==null||path.isEmpty())path="/";
            if(!path.startsWith("/"))throw new IllegalArgumentException("Invalid origin path");
            if(absolute.getRawQuery()!=null)path+="?"+absolute.getRawQuery();
            StringBuilder forwarded=new StringBuilder(start[0]).append(' ').append(path).append(" HTTP/1.1\r\n");
            for(Map.Entry<String,String> header:headers.entrySet())if(!hop.contains(header.getKey()))
                forwarded.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
            forwarded.append("connection: close\r\n\r\n");
            return new Request(Protocol.HTTP_FORWARD,target,forwarded.toString().getBytes(StandardCharsets.US_ASCII),length,chunked);
        } catch (IllegalArgumentException malformed) { httpStatus(out, "400 Bad Request", ""); return null; }
    }
    private static Target httpAuthority(String authority){
        if(authority==null||authority.isEmpty()||authority.indexOf('@')>=0)throw new IllegalArgumentException("Invalid HTTP authority");
        if(authority.startsWith("[")){
            int end=authority.indexOf(']');if(end<0)throw new IllegalArgumentException("Invalid IPv6 authority");
            return Target.authority(end==authority.length()-1?authority+":80":authority);
        }
        return Target.authority(authority.indexOf(':')<0?authority+":80":authority);
    }
    private static String line(InputStream in, int first, int[] budget) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        for (;;) {
            int c = first >= 0 ? first : octet(in); first = -1;
            if (--budget[0] < 0) throw new IOException("Proxy header limit exceeded");
            if (c == '\r') {
                if (--budget[0] < 0 || octet(in) != '\n') throw new IOException("Invalid proxy line ending");
                return new String(result.toByteArray(), StandardCharsets.US_ASCII);
            }
            if ((c < 32 && c != '\t') || c > 126) throw new IOException("Invalid proxy header byte");
            result.write(c);
        }
    }
    private static int octet(InputStream in) throws IOException { int value = in.read(); if (value < 0) throw new EOFException("Short proxy handshake"); return value; }
    private static byte[] bytes(InputStream in, int count) throws IOException {
        byte[] result = new byte[count];
        for (int i = 0; i < count; i++) result[i] = (byte)octet(in);
        return result;
    }
    private static void socksFailure(OutputStream out, int status) throws IOException {
        out.write(new byte[]{5, (byte)status, 0, 1, 0, 0, 0, 0, 0, 0}); out.flush();
    }
    private static void httpStatus(OutputStream out, String status, String extra) throws IOException {
        String headers = status.startsWith("200 ") ? "" : "Connection: close\r\nContent-Length: 0\r\n";
        out.write(("HTTP/1.1 " + status + "\r\n" + headers + extra + "\r\n").getBytes(StandardCharsets.US_ASCII)); out.flush();
    }
    private static void wipe(byte[] bytes) { if (bytes != null) Arrays.fill(bytes, (byte)0); }
}
