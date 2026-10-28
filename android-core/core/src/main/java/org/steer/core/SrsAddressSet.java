package org.steer.core;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.util.*;
import java.util.zip.*;
import org.json.*;

/** Compact, address-only SRS reader; no sing-box process, resolver or JSON
 * expansion of large lists. NOT wired to public capability admission yet.
 * Format references: SagerNet/sing-box v1.13.0 common/srs/{binary,ip_set}.go;
 * SagerNet/sing e419e9875a07 common/domain/{set,matcher,adguard_matcher}.go. Independent BFS
 * edge offsets replace the upstream rank/select implementation. Unsupported
 * non-address fields explicitly refuse, never silently vanish. Address unions,
 * logical AND/OR, bounded literal keywords/linear ASCII domain regexes and
 * inversion retain their matching semantics. Unsupported regex constructs and
 * bounded ASCII AdGuard anchors/wildcards retain their semantics. Unsupported
 * source/port conditions and non-ASCII AdGuard keys reject the whole set. */
public final class SrsAddressSet {
    public static final class Budget {
        private long remaining;
        public Budget(long bytes){if(bytes<1||bytes>128L*1024*1024)throw new IllegalArgumentException("Bounded rule-set budget required");remaining=bytes;}
        void claim(long bytes)throws IOException{
            if(bytes<0||bytes>remaining)throw new IOException("Rule-set memory budget exceeded");remaining-=bytes;
        }
    }
    private final List<Row> rows;
    private final boolean domains,ips;
    private SrsAddressSet(List<Row> rows,boolean domains,boolean ips){this.rows=Collections.unmodifiableList(rows);this.domains=domains;this.ips=ips;}
    public boolean hasDomains(){return domains;}
    public boolean hasIps(){return ips;}
    /** Same destination-address merge boundary as sing-box's single default,
     * non-inverted headless rule. Logical/multiple/inverted sets must NOT be
     * flattened into the outer rule's destination-address union. */
    public boolean mergeableAddressGroup(){return rows.size()==1&&rows.get(0).children==null&&!rows.get(0).invert;}
    public static SrsAddressSet logical(List<SrsAddressSet> sets,boolean and,boolean invert,Budget budget)throws IOException{
        if(sets==null||sets.isEmpty()||sets.size()>256||budget==null)throw new IOException("Bounded nonempty address composition required");
        budget.claim(64L+sets.size()*16L);Row result=new Row();result.and=and;result.invert=invert;
        List<Row> children=new ArrayList<>(sets.size());
        for(SrsAddressSet set:sets){
            if(set==null)throw new IOException("Missing address composition input");
            Row child;
            if(set.rows.size()==1)child=set.rows.get(0);
            else{
                budget.claim(64L+set.rows.size()*8L);child=new Row();child.children=set.rows;
                child.hasDomains=set.domains;child.hasIps=set.ips;
            }
            children.add(child);result.hasDomains|=set.domains;result.hasIps|=set.ips;
        }
        result.children=Collections.unmodifiableList(children);
        return new SrsAddressSet(Collections.singletonList(result),result.hasDomains,result.hasIps);
    }
    /** Only the exact single-row source JSON emitted by host GeoDataConfig.convert.
     * Provenance/hash/path admission belongs to the host binding, not this parser.
     * No DAT fetch, source path, resolver or public capability activation here. */
    public static SrsAddressSet fromGeoJson(JSONObject source,Budget budget)throws IOException{
        if(source==null||budget==null)throw new IOException("Bound Geo source required");
        try{
            if(source.length()!=2||!source.has("version")||!source.has("rules")||
                !(source.opt("version") instanceof Integer||source.opt("version") instanceof Long)||source.getLong("version")!=3)
                throw new IOException("Exact host Geo source schema required");
            JSONArray rows=source.getJSONArray("rules");if(rows.length()!=1)throw new IOException("Single host Geo row required");
            JSONObject value=rows.getJSONObject(0);Set<String> known=new HashSet<>(Arrays.asList("domain","domain_suffix","domain_keyword","domain_regex","ip_cidr","invert"));
            for(Iterator<String> it=value.keys();it.hasNext();)if(!known.contains(it.next()))throw new IOException("Unsupported Geo condition");
            budget.claim(64);Row row=new Row();int[] total={0,0,0,0,0};
            if(value.has("invert")){if(!(value.opt("invert") instanceof Boolean))throw new IOException("Geo inversion type");row.invert=value.getBoolean("invert");}
            if(value.has("domain")||value.has("domain_suffix"))row.domain=Trie.fromGeo(value,budget);
            if(value.has("domain_keyword"))row.keywords=geoTexts(value.getJSONArray("domain_keyword"),budget,total,1,4096,1024);
            if(value.has("domain_regex"))row.regexes=compileRegexes(geoTexts(value.getJSONArray("domain_regex"),budget,total,3,128,1024),budget,total);
            if(value.has("ip_cidr"))row.ip=Ranges.fromGeo(value.getJSONArray("ip_cidr"),budget);
            row.hasDomains=row.domain!=null||row.keywords!=null||row.regexes!=null;row.hasIps=row.ip!=null;
            if(!row.hasDomains&&!row.hasIps)throw new IOException("Empty Geo row");
            return new SrsAddressSet(Collections.singletonList(row),row.hasDomains,row.hasIps);
        }catch(JSONException|IllegalArgumentException invalid){throw new IOException("Invalid bounded host Geo source",invalid);}
    }
    private static List<String> geoTexts(JSONArray values,Budget budget,int[] total,int counter,int limit,int maxLength)throws IOException,JSONException{
        int count=values.length();if(count<1||count>limit||total[counter]>limit-count)throw new IOException("Geo text count capacity");
        total[counter]+=count;budget.claim(count*16L);List<String> result=new ArrayList<>(count);
        for(int at=0;at<count;at++){
            Object raw=values.get(at);if(!(raw instanceof String))throw new IOException("Geo text type");String text=(String)raw;
            if(text.isEmpty()||text.length()>maxLength)throw new IOException("Geo text length capacity");
            budget.claim(96+text.length()*6L);
            byte[] encoded=text.getBytes(StandardCharsets.UTF_8);
            if(encoded.length>1024||total[2]>1024*1024-encoded.length)throw new IOException("Geo text byte capacity");
            total[2]+=encoded.length;result.add(text);
        }
        return Collections.unmodifiableList(result);
    }
    public boolean matches(String domain,byte[] address){
        if(address!=null&&((address.length!=4&&address.length!=16)||Ipv6Routes.mappedIpv4(address)))return false;
        String normalized=domain==null?null:DomainNames.normalize(domain);
        for(Row row:rows)if(row.matches(normalized,address))return true;
        return false;
    }
    /** Input bytes must separately be bound to the trusted catalogue/digest.
     * Strict parsing alone does not establish asset provenance. */
    public static SrsAddressSet read(byte[] packed,Budget budget)throws IOException{
        if(packed==null||packed.length<6||packed.length>8*1024*1024||budget==null||
            packed[0]!='S'||packed[1]!='R'||packed[2]!='S'||packed[3]<1||packed[3]>3)
            throw new IOException("Unsupported bounded SRS header/version");
        byte[] plain=inflate(packed,budget);
        try(DataInputStream input=new DataInputStream(new ByteArrayInputStream(plain))){
            int count=number(input,4096);if(count==0)throw new IOException("Empty rule-set");
            List<Row> rows=new ArrayList<>(count);boolean domains=false,ips=false;int[] total={0,0,0,0,0};
            for(int at=0;at<count;at++){
                Row row=readRow(input,budget,0,total);rows.add(row);domains|=row.hasDomains;ips|=row.hasIps;
            }
            if(input.read()!=-1)throw new IOException("Trailing unparsed SRS data");
            return new SrsAddressSet(rows,domains,ips);
        }
    }
    private static byte[] inflate(byte[] packed,Budget budget)throws IOException{
        Inflater inflater=new Inflater();inflater.setInput(packed,4,packed.length-4);
        try{
            ByteArrayOutputStream result=new ByteArrayOutputStream();byte[] part=new byte[8192];
            while(!inflater.finished()){
                int got=inflater.inflate(part);
                if(got==0){if(inflater.finished())break;throw new IOException("Incomplete/dictionary SRS compression");}
                if(result.size()>32*1024*1024-got)throw new IOException("Inflated rule-set exceeds32 MiB");
                budget.claim(got*2L); // output plus final copy, before allocation/growth
                result.write(part,0,got);
            }
            if(inflater.getRemaining()!=0)throw new IOException("Trailing compressed SRS data");
            return result.toByteArray();
        }catch(DataFormatException invalid){throw new IOException("Invalid SRS compression");}
        finally{inflater.end();}
    }
    private static int number(DataInputStream input,int max)throws IOException{
        long result=0;int shift=0;
        for(int at=0;at<5;at++){
            int next=input.readUnsignedByte();result|=(long)(next&127)<<shift;
            if((next&128)==0){if(result>max||at>0&&(next&127)==0)throw new IOException("Noncanonical/oversized SRS length");return (int)result;}
            shift+=7;
        }
        throw new IOException("SRS length overflow");
    }
    private static boolean flag(DataInputStream input)throws IOException{
        int value=input.readUnsignedByte();if(value>1)throw new IOException("Boolean SRS inversion required");return value==1;
    }
    private static List<String> texts(DataInputStream input,Budget budget,int[] total,int counter,int limit)throws IOException{
        int count=number(input,limit);
        if(count==0||total[counter]>limit-count)throw new IOException("SRS domain text count capacity");
        total[counter]+=count;budget.claim(count*8L);List<String> result=new ArrayList<>(count);
        for(int at=0;at<count;at++){
            int size=number(input,1024);
            if(total[2]>1024*1024-size)throw new IOException("SRS domain text byte capacity");
            total[2]+=size;budget.claim(96+size*6L);
            byte[] bytes=new byte[size];input.readFully(bytes);
            // No replacement characters/case-folding of configured keywords:
            // upstream lowercases the domain, not the literal substring.
            result.add(StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString());
        }
        return Collections.unmodifiableList(result);
    }
    private static List<LinearDomainRegex> regexes(DataInputStream input,Budget budget,int[] total)throws IOException{
        return compileRegexes(texts(input,budget,total,3,128),budget,total);
    }
    private static List<LinearDomainRegex> compileRegexes(List<String> patterns,Budget budget,int[] total)throws IOException{
        List<LinearDomainRegex> result=new ArrayList<>(patterns.size());
        for(String pattern:patterns){
            budget.claim(512L*256); // bounded compiler/AST/NFA memory before materialization
            final LinearDomainRegex compiled;
            try{compiled=LinearDomainRegex.compile(pattern);}catch(IllegalArgumentException unsupported){throw new IOException("Unsupported bounded domain regex");}
            if(total[4]>16384-compiled.stateCount())throw new IOException("SRS regex state capacity");
            total[4]+=compiled.stateCount();result.add(compiled);
        }
        return Collections.unmodifiableList(result);
    }
    private static Row readRow(DataInputStream input,Budget budget,int depth,int[] total)throws IOException{
        if(depth>16||++total[0]>4096)throw new IOException("SRS rule tree depth/capacity");
        budget.claim(64);Row row=new Row();int type=input.readUnsignedByte();
        if(type==0){
            for(;;){
                int item=input.readUnsignedByte();
                if(item==255){row.invert=flag(input);break;}
                if(item==2&&row.domain==null){row.domain=Trie.read(input,budget);row.hasDomains=true;}
                else if(item==16&&row.adguard==null){row.adguard=Trie.read(input,budget,true);row.hasDomains=true;}
                else if(item==3&&row.keywords==null){row.keywords=texts(input,budget,total,1,4096);row.hasDomains=true;}
                else if(item==4&&row.regexes==null){row.regexes=regexes(input,budget,total);row.hasDomains=true;}
                else if(item==6&&row.ip==null){row.ip=Ranges.read(input,budget);row.hasIps=true;}
                else throw new IOException("Unsupported or duplicate SRS address condition");
            }
            if(row.domain==null&&row.adguard==null&&row.keywords==null&&row.regexes==null&&row.ip==null)throw new IOException("Empty SRS address rule");
        }else if(type==1){
            int mode=input.readUnsignedByte();if(mode>1)throw new IOException("Unknown SRS logical mode");row.and=mode==0;
            int count=number(input,4096);if(count==0||count>4096-total[0])throw new IOException("SRS logical child capacity");
            budget.claim(count*8L);List<Row> children=new ArrayList<>(count);
            for(int at=0;at<count;at++){
                Row child=readRow(input,budget,depth+1,total);children.add(child);row.hasDomains|=child.hasDomains;row.hasIps|=child.hasIps;
            }
            row.children=Collections.unmodifiableList(children);row.invert=flag(input);
        }else throw new IOException("Unknown SRS rule type");
        return row;
    }
    private static final class Row {
        Trie domain,adguard;Ranges ip;List<String> keywords;List<LinearDomainRegex> regexes;List<Row> children;boolean and,invert,hasDomains,hasIps;
        boolean matches(String name,byte[] address){
            boolean matched;
            if(children==null){
                matched=domain!=null&&name!=null&&domain.matches(name)||ip!=null&&address!=null&&ip.matches(address);
                if(!matched&&name!=null&&adguard!=null)matched=adguard.matchesAdguard(name);
                if(!matched&&name!=null&&!name.isEmpty()&&keywords!=null)
                    for(String word:keywords)if(name.contains(word)){matched=true;break;}
                if(!matched&&name!=null&&!name.isEmpty()&&regexes!=null)
                    for(LinearDomainRegex regex:regexes)if(regex.matches(name)){matched=true;break;}
            }
            else{
                matched=and;
                for(Row child:children)if(child.matches(name,address)!=and){matched=!and;break;}
            }
            return matched!=invert;
        }
    }
    private static final class Trie {
        final long[] leaves;final byte[] labels;final int[] starts;
        Trie(long[] leaves,byte[] labels,int[] starts){this.leaves=leaves;this.labels=labels;this.starts=starts;}
        /** Build compact BFS arrays directly from sorted reversed host names;
         * no object-per-character trie or JSON-to-SRS compression roundtrip. */
        static Trie fromGeo(JSONObject row,Budget budget)throws IOException,JSONException{
            int count=0;for(String field:Arrays.asList("domain","domain_suffix"))if(row.has(field)){
                int size=row.getJSONArray(field).length();if(size<1||count>200000-size)throw new IOException("Geo domain count capacity");count+=size;
            }
            budget.claim(count*16L);List<String> keys=new ArrayList<>(count);int maxNodes=1;
            for(String field:Arrays.asList("domain","domain_suffix"))if(row.has(field)){
                JSONArray names=row.getJSONArray(field);
                for(int at=0;at<names.length();at++){
                    Object raw=names.get(at);if(!(raw instanceof String)||((String)raw).length()>254)throw new IOException("Geo domain type/length");
                    String name=(String)raw;boolean suffix=field.equals("domain_suffix"),subOnly=suffix&&name.startsWith(".");
                    budget.claim(96+name.length()*6L);
                    name=DomainNames.normalize(subOnly?name.substring(1):name);
                    String key=new StringBuilder(subOnly?"."+name:name).reverse().toString();
                    if(suffix)key+=(char)(subOnly?13:10);
                    if(key.length()>254||maxNodes>4194304-key.length())throw new IOException("Geo compact trie capacity");
                    maxNodes+=key.length();keys.add(key);
                }
            }
            Collections.sort(keys);budget.claim(maxNodes*22L+64);
            int[] low=new int[maxNodes],high=new int[maxNodes],starts=new int[maxNodes+1];short[] depth=new short[maxNodes];
            byte[] labels=new byte[maxNodes-1];long[] leaves=new long[(maxNodes+63)/64];high[0]=keys.size();int nodes=1;
            for(int node=0;node<nodes;node++){
                int at=low[node],end=high[node],level=depth[node];starts[node]=nodes-1;
                while(at<end&&keys.get(at).length()==level){leaves[node>>>6]|=1L<<(node&63);at++;}
                while(at<end){
                    int first=at;char label=keys.get(at).charAt(level);
                    while(at<end&&keys.get(at).charAt(level)==label)at++;
                    int child=nodes++;labels[child-1]=(byte)label;low[child]=first;high[child]=at;depth[child]=(short)(level+1);
                }
            }
            starts[nodes]=nodes-1;
            return new Trie(Arrays.copyOf(leaves,(nodes+63)/64),Arrays.copyOf(labels,nodes-1),Arrays.copyOf(starts,nodes+1));
        }
        static long[] words(DataInputStream input,Budget budget,int max)throws IOException{
            int count=number(input,max);budget.claim(count*8L);long[] result=new long[count];
            for(int at=0;at<count;at++)result[at]=input.readLong();return result;
        }
        static boolean bit(long[] words,int bit){return bit>=0&&(bit>>>6)<words.length&&(words[bit>>>6]&(1L<<(bit&63)))!=0;}
        static Trie read(DataInputStream input,Budget budget)throws IOException{
            return read(input,budget,false);
        }
        static Trie read(DataInputStream input,Budget budget,boolean adguard)throws IOException{
            if(input.readUnsignedByte()!=0)throw new IOException("Unknown succinct-domain format");
            long[] leaves=words(input,budget,65536),bitmap=words(input,budget,131072);
            int size=number(input,4*1024*1024-1),nodes=size+1;
            budget.claim(size+4L*(nodes+1));byte[] labels=new byte[size];input.readFully(labels);
            if(leaves.length!=(nodes+63)/64||bitmap.length!=(2L*nodes-1+63)/64||bit(leaves,0))throw new IOException("Invalid succinct-domain shape");
            int[] starts=new int[nodes+1];int edge=0,position=0;
            for(int node=0;node<nodes;node++){
                starts[node]=edge;int previous=-1;
                while(!bit(bitmap,position)){
                    if(position>=2*nodes-1||edge>=size||edge+1<=node)throw new IOException("Disconnected domain trie");
                    int label=labels[edge]&255;
                    boolean ordinary=label=='.'||label=='-'||label=='_'||label>='0'&&label<='9'||label>='a'&&label<='z';
                    boolean extra=adguard&&(label=='*'||label==8||label>='A'&&label<='Z');
                    if(label<=previous||(!ordinary&&!extra&&label!=10&&label!=13))throw new IOException("Invalid/unsorted domain label");
                    previous=label;edge++;position++;
                }
                position++;
            }
            starts[nodes]=edge;
            if(edge!=size||position!=2*nodes-1)throw new IOException("Domain trie node count mismatch");
            for(int bit=nodes;bit<leaves.length*64;bit++)if(bit(leaves,bit))throw new IOException("Nonzero domain leaf padding");
            for(int bit=position;bit<bitmap.length*64;bit++)if(bit(bitmap,bit))throw new IOException("Nonzero domain bitmap padding");
            // Bounded BFS validates depth and special suffix-marker leaves.
            budget.claim(nodes*(adguard?4L:2L));short[] depth=new short[nodes],wildDepth=adguard?new short[nodes]:null;
            for(int node=0;node<nodes;node++)for(int at=starts[node];at<starts[node+1];at++){
                int child=at+1,label=labels[at]&255;depth[child]=(short)(depth[node]+1);
                if(depth[child]>(adguard?512:254))throw new IOException("Domain trie depth exceeds hostname bound");
                if(adguard){
                    wildDepth[child]=(short)(wildDepth[node]+(label=='*'||label==8?1:0));
                    if(wildDepth[child]>100)throw new IOException("AdGuard wildcard depth capacity");
                    if(label==8&&(node!=0||bit(leaves,child)))throw new IOException("Invalid AdGuard open marker");
                    if((label==10||label==13)&&(node==0||!bit(leaves,child)||starts[child]!=starts[child+1]||labels[node-1]==8))throw new IOException("Invalid AdGuard anchor");
                    continue;
                }
                if((label==10||label==13)&&(node==0||!bit(leaves,child)||starts[child]!=starts[child+1]||
                    label==13&&(labels[node-1]&255)!='.'))throw new IOException("Invalid domain suffix marker");
            }
            if(adguard)budget.claim(1024L*1024); // fixed sparse query frontier workspace
            return new Trie(leaves,labels,starts);
        }
        /** Independent subset simulation over the compact reversed trie: no
         * materialized pattern list, recursive globbing or backtracking regex.
         * Low state bit means a wildcard loop; a deduplicated work queue
         * computes epsilon closure without allocating per-pattern objects.
         * Work exhaustion THROWS (also under inversion), never a false match. */
        boolean matchesAdguard(String domain){
            int[] work={0};
            Frontier first=new Frontier(),second=new Frontier();
            if(adguardAt(domain,0,0,work,first,second))return true;
            int open=-1;for(int edge=starts[0];edge<starts[1];edge++)if(labels[edge]==8){open=edge+1;break;}
            if(open<0)return false;
            // Preserve the upstream literal-open entry at each label suffix,
            // separately from the wildcard interpretation of the open edge.
            for(int offset=0;;){
                if(adguardAt(domain,offset,open,work,first,second))return true;
                int next=offset;while(next<domain.length()&&domain.charAt(domain.length()-1-next)!='.')next++;
                if(next>=domain.length())return false;offset=next+1;
            }
        }
        private static final class Frontier {
            private final int[] states=new int[32768],touched=new int[32768],slots=new int[65536];
            private int size;
            void add(int state,int[] work){
                int encoded=state+1,at=(state*0x9e3779b9)>>>16;
                for(;;at=(at+1)&65535){
                    if(++work[0]>262144)throw new IllegalStateException("AdGuard matching work capacity");
                    if(slots[at]==encoded)return;
                    if(slots[at]!=0)continue;
                    if(size==states.length)throw new IllegalStateException("AdGuard frontier capacity");
                    slots[at]=encoded;states[size]=state;touched[size++]=at;return;
                }
            }
            void clear(){for(int at=0;at<size;at++)slots[touched[at]]=0;size=0;}
        }
        private boolean adguardAt(String domain,int offset,int start,int[] work,Frontier current,Frontier next){
            current.clear();next.clear();current.add(start*2,work);
            for(int position=offset;;position++){
                int ch=position<domain.length()?domain.charAt(domain.length()-1-position):-1;
                for(int at=0;at<current.size;at++){
                    int state=current.states[at];
                    if(++work[0]>262144)throw new IllegalStateException("AdGuard matching work capacity");
                    int node=state>>>1;
                    if(ch<0&&bit(leaves,node))return true;
                    if(ch>=0&&(state&1)!=0)next.add(state,work);
                    for(int edge=starts[node];edge<starts[node+1];edge++){
                        if(++work[0]>262144)throw new IllegalStateException("AdGuard matching work capacity");
                        int label=labels[edge]&255,child=edge+1;
                        if(label==13||label==10&&(ch<0||ch=='.'))return true;
                        if(label=='*'||label==8)current.add(child*2+1,work);
                        else if(ch>=0&&label==ch)next.add(child*2,work);
                    }
                }
                if(ch<0||next.size==0)return false;
                Frontier retired=current;current=next;next=retired;next.clear();
            }
        }
        boolean matches(String domain){
            int node=0,at=domain.length()-1;
            for(;;){
                if(at<0&&bit(leaves,node))return true;
                int found=-1;
                for(int edge=starts[node];edge<starts[node+1];edge++){
                    int label=labels[edge]&255;
                    if(label==13||label==10&&(at<0||domain.charAt(at)=='.'))return true;
                    if(at>=0&&label==domain.charAt(at))found=edge+1;
                }
                if(found<0||at<0)return false;node=found;at--;
            }
        }
    }
    private static final class Ranges {
        final byte[] families,from,to;
        Ranges(byte[] families,byte[] from,byte[] to){this.families=families;this.from=from;this.to=to;}
        private static final class GeoRange {
            final int family;final byte[] from=new byte[16],to=new byte[16];
            GeoRange(String cidr){
                if(cidr.contains(":")){
                    Ipv6Routes.Prefix prefix=Ipv6Routes.parse(cidr);family=16;
                    byte[] address=prefix.addressBytes();if(Ipv6Routes.mappedIpv4(address))throw new IllegalArgumentException("Mapped Geo IP refused");
                    System.arraycopy(address,0,from,0,16);System.arraycopy(address,0,to,0,16);
                    for(int bit=prefix.bits;bit<128;bit++)to[bit/8]|=1<<(7-bit%8);
                }else{
                    Ipv4Routes.Prefix prefix=Ipv4Routes.parse(cidr);family=4;
                    long last=prefix.network+(prefix.bits==0?0xffffffffL:(1L<<(32-prefix.bits))-1);
                    for(int at=0;at<4;at++){from[at]=(byte)(prefix.network>>>(24-at*8));to[at]=(byte)(last>>>(24-at*8));}
                }
            }
        }
        static Ranges fromGeo(JSONArray prefixes,Budget budget)throws IOException,JSONException{
            int count=prefixes.length();if(count<1||count>250000)throw new IOException("Geo CIDR count capacity");
            budget.claim(count*176L);List<GeoRange> ranges=new ArrayList<>(count);
            for(int at=0;at<count;at++){
                Object text=prefixes.get(at);if(!(text instanceof String)||((String)text).length()>64)throw new IOException("Geo CIDR type/length");
                ranges.add(new GeoRange((String)text));
            }
            ranges.sort((left,right)->left.family!=right.family?left.family-right.family:compare(left.from,0,right.from,0,left.family));
            List<GeoRange> merged=new ArrayList<>(count);
            for(GeoRange next:ranges){
                GeoRange last=merged.isEmpty()?null:merged.get(merged.size()-1);
                if(last!=null&&last.family==next.family&&compare(next.from,0,last.to,0,last.family)<=0){
                    if(compare(next.to,0,last.to,0,last.family)>0)System.arraycopy(next.to,0,last.to,0,last.family);
                }else merged.add(next);
            }
            int size=merged.size();byte[] families=new byte[size],from=new byte[size*16],to=new byte[size*16];
            for(int at=0;at<size;at++){GeoRange range=merged.get(at);families[at]=(byte)range.family;System.arraycopy(range.from,0,from,at*16,range.family);System.arraycopy(range.to,0,to,at*16,range.family);}
            return new Ranges(families,from,to);
        }
        static Ranges read(DataInputStream input,Budget budget)throws IOException{
            if(input.readUnsignedByte()!=1)throw new IOException("Unknown SRS IP-set format");
            long size=input.readLong();if(size<1||size>250000)throw new IOException("SRS IP range capacity");int count=(int)size;
            budget.claim(count*33L);byte[] families=new byte[count],from=new byte[count*16],to=new byte[count*16];
            int previous=0;
            for(int at=0;at<count;at++){
                int family=number(input,16);if(family!=4&&family!=16||family<previous)throw new IOException("SRS IP family/order");
                input.readFully(from,at*16,family);if(number(input,16)!=family)throw new IOException("Mixed SRS IP range family");
                input.readFully(to,at*16,family);families[at]=(byte)family;
                if(family==16&&(Ipv6Routes.mappedIpv4(Arrays.copyOfRange(from,at*16,at*16+16))||Ipv6Routes.mappedIpv4(Arrays.copyOfRange(to,at*16,at*16+16))))throw new IOException("Mapped SRS IP range unsupported");
                if(compare(from,at*16,to,at*16,family)>0||at>0&&family==previous&&compare(to,(at-1)*16,from,at*16,family)>=0)throw new IOException("Unordered/overlapping SRS IP ranges");
                previous=family;
            }
            return new Ranges(families,from,to);
        }
        static int compare(byte[] left,int l,byte[] right,int r,int size){
            for(int at=0;at<size;at++){int delta=(left[l+at]&255)-(right[r+at]&255);if(delta!=0)return delta;}return 0;
        }
        boolean matches(byte[] address){
            int low=0,high=families.length-1;
            while(low<=high){
                int middle=(low+high)>>>1,family=families[middle]&255;
                if(family<address.length){low=middle+1;continue;}if(family>address.length){high=middle-1;continue;}
                if(compare(address,0,from,middle*16,family)<0)high=middle-1;
                else if(compare(address,0,to,middle*16,family)>0)low=middle+1;
                else return true;
            }
            return false;
        }
    }
}
