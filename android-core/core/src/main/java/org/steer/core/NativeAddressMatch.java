package org.steer.core;

import org.json.*;
import java.io.IOException;
import java.util.*;

/** SOURCE ONLY address-subset compiler for preserved nativeMatch. NOT worker
 * admission: package/process/port/network/source-address keys explicitly fail.
 * Single default non-inverted Geo sets merge into the destination-address
 * group; other sets retain the outer group's AND constraint. See pinned host
 * sing-box route/rule/{rule_abstract,rule_item_rule_set}.go, not guessed AND/OR. */
public final class NativeAddressMatch {
    private NativeAddressMatch() {}
    public interface Sets { SrsAddressSet load(String reference)throws IOException; }
    public static SrsAddressSet compile(JSONObject source,Sets sets,SrsAddressSet.Budget budget)throws IOException {
        if(source==null||budget==null)throw new IOException("Bound native address match required");
        return compileText(source.toString(),sets,budget);
    }
    /** Cache owners compile the EXACT captured text used for the cache key,
     * not a second serialization of a potentially changed caller JSONObject. */
    public static SrsAddressSet compileText(String text,Sets sets,SrsAddressSet.Budget budget)throws IOException {
        if(text==null||budget==null||text.length()>262144)throw new IOException("Native address source bound");
        budget.claim(1024L+text.length()*8L);
        try{
            return row(new JSONObject(text),sets,budget,0,new int[]{0});
        }
        catch(JSONException|IllegalArgumentException invalid){throw new IOException("Invalid native address match");}
    }
    private static void fields(JSONObject row,String... allowed)throws IOException {
        Set<String> keys=new HashSet<>(Arrays.asList(allowed));
        for(Iterator<String> it=row.keys();it.hasNext();)if(!keys.contains(it.next()))throw new IOException("Unsupported native address condition");
    }
    private static SrsAddressSet compose(List<SrsAddressSet> sets,boolean and,boolean invert,SrsAddressSet.Budget budget)throws IOException {
        if(sets.size()==1&&!invert)return sets.get(0);
        return SrsAddressSet.logical(sets,and,invert,budget);
    }
    private static JSONArray strings(Object raw,int limit)throws IOException,JSONException {
        JSONArray values=raw instanceof String?new JSONArray().put(raw):raw instanceof JSONArray?(JSONArray)raw:null;
        if(values==null||values.length()<1||values.length()>limit)throw new IOException("Native address string list bound");
        for(int i=0;i<values.length();i++)if(!(values.get(i) instanceof String))throw new IOException("Native address string required");
        return values;
    }
    private static SrsAddressSet row(JSONObject value,Sets resolver,SrsAddressSet.Budget budget,int depth,int[] nodes)throws IOException,JSONException {
        if(depth>16||++nodes[0]>4096)throw new IOException("Native address tree bound");
        if(value.has("invert")&&!(value.opt("invert") instanceof Boolean))throw new IOException("Native address inversion type");
        boolean invert=value.optBoolean("invert",false);
        if(value.has("type")&&!(value.opt("type") instanceof String))throw new IOException("Native address type");
        String type=value.optString("type","default");
        if(type.equals("logical")){
            fields(value,"type","mode","rules","invert");
            if(!"and".equals(value.opt("mode"))&&!"or".equals(value.opt("mode")))throw new IOException("Native address logical mode");
            JSONArray children=value.getJSONArray("rules");if(children.length()<1||children.length()>256)throw new IOException("Native logical child bound");
            List<SrsAddressSet> sets=new ArrayList<>(children.length());
            for(int i=0;i<children.length();i++)sets.add(row(children.getJSONObject(i),resolver,budget,depth+1,nodes));
            return SrsAddressSet.logical(sets,value.getString("mode").equals("and"),invert,budget);
        }
        if(!type.equals("default"))throw new IOException("Unsupported native address type");
        fields(value,"type","invert","domain","domain_suffix","domain_keyword","domain_regex","ip_cidr","rule_set");
        JSONObject address=new JSONObject();
        for(String key:Arrays.asList("domain","domain_suffix","domain_keyword","domain_regex","ip_cidr"))
            if(value.has(key))address.put(key,strings(value.get(key),100000));
        SrsAddressSet outer=address.length()==0?null:SrsAddressSet.fromGeoJson(
            new JSONObject().put("version",3).put("rules",new JSONArray().put(address)),budget);
        List<SrsAddressSet> branches=new ArrayList<>();
        if(value.has("rule_set")){
            JSONArray references=strings(value.get("rule_set"),64);if(resolver==null)throw new IOException("Pinned native address resolver required");
            for(int i=0;i<references.length();i++){
                String ref=references.getString(i);if(!ref.matches("[A-Za-z0-9_.-]{1,64}"))
                    throw new IOException("Unbound native Geo reference");
                SrsAddressSet set=resolver.load(ref);if(set==null)throw new IOException("Missing pinned native Geo set");
                // For the mergeable single address group, the host combines
                // destination requirements/satisfaction, not boolean AND.
                branches.add(outer==null?set:compose(Arrays.asList(outer,set),!set.mergeableAddressGroup(),false,budget));
            }
        }else if(outer!=null)branches.add(outer);
        if(branches.isEmpty())throw new IOException("Empty native address condition");
        // Keep an explicit rule_set wrapper even for a singleton: the host
        // does not treat a rule containing another rule_set as mergeable.
        return value.has("rule_set")?SrsAddressSet.logical(branches,false,invert,budget):compose(branches,false,invert,budget);
    }
}
