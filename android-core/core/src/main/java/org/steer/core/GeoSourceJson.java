package org.steer.core;

import org.json.*;
import java.io.IOException;
import java.util.*;

/** Strict bounded syntax for host-generated Geo source JSON, before Android's
 * permissive JSONObject parser. This establishes syntax only, not provenance. */
public final class GeoSourceJson {
    private GeoSourceJson() {}
    public static JSONObject parse(String text)throws IOException {
        if(text==null||text.length()<2||text.length()>8*1024*1024)throw new IOException("Geo source text bound");
        Reader reader=new Reader(text);reader.space();
        if(reader.peek()!='{')throw new IOException("Geo source object required");
        reader.value(0);reader.space();if(reader.at!=text.length())throw new IOException("Geo source trailing text");
        try{return new JSONObject(text);}catch(JSONException bad){throw new IOException("Invalid Geo source JSON",bad);}
    }
    private static final class Reader {
        final String text;int at,objects,arrays;
        Reader(String value){text=value;}
        int peek(){return at<text.length()?text.charAt(at):-1;}
        void space(){while(at<text.length()&&" \t\r\n".indexOf(text.charAt(at))>=0)at++;}
        void take(char ch)throws IOException{space();if(peek()!=ch)throw new IOException("Geo source separator");at++;}
        boolean eat(char ch){space();if(peek()!=ch)return false;at++;return true;}
        void value(int depth)throws IOException {
            if(depth>6)throw new IOException("Geo source depth bound");space();int ch=peek();
            if(ch=='{'){
                if(++objects>2)throw new IOException("Geo source object bound");at++;Set<String> keys=new HashSet<>();
                if(eat('}'))return;
                do{
                    space();int begin=at;string(true);String key=text.substring(begin+1,at-1);
                    if(!keys.add(key)||keys.size()>8)throw new IOException("Duplicate/excess Geo source key");
                    take(':');value(depth+1);
                    if(eat('}'))return;take(',');
                }while(true);
            }
            if(ch=='['){
                if(++arrays>8)throw new IOException("Geo source array bound");at++;if(eat(']'))return;
                do{value(depth+1);if(eat(']'))return;take(',');}while(true);
            }
            if(ch=='"'){string(false);return;}
            if(ch=='t'){literal("true");return;}if(ch=='f'){literal("false");return;}if(ch=='n'){literal("null");return;}
            if(ch=='-'||digit(ch)){number();return;}throw new IOException("Geo source token");
        }
        void literal(String value)throws IOException {
            if(!text.startsWith(value,at))throw new IOException("Geo source literal");at+=value.length();
        }
        static boolean digit(int ch){return ch>='0'&&ch<='9';}
        void number()throws IOException {
            if(peek()=='-')at++;if(peek()=='0')at++;
            else{if(peek()<'1'||peek()>'9')throw new IOException("Geo source number");while(digit(peek()))at++;}
            if(peek()=='.'){at++;if(!digit(peek()))throw new IOException("Geo source fraction");while(digit(peek()))at++;}
            if(peek()=='e'||peek()=='E'){
                at++;if(peek()=='+'||peek()=='-')at++;if(!digit(peek()))throw new IOException("Geo source exponent");while(digit(peek()))at++;
            }
        }
        int hex()throws IOException {
            if(at>text.length()-4)throw new IOException("Short Geo source escape");int value=0;
            for(int i=0;i<4;i++){
                char ch=text.charAt(at++);int digit=ch>='0'&&ch<='9'?ch-'0':ch>='a'&&ch<='f'?ch-'a'+10:ch>='A'&&ch<='F'?ch-'A'+10:-1;
                if(digit<0)throw new IOException("Geo source hex escape");value=(value<<4)|digit;
            }return value;
        }
        void string(boolean key)throws IOException {
            if(peek()!='"')throw new IOException("Quoted Geo source string required");at++;int begin=at;
            while(at<text.length()){
                char ch=text.charAt(at++);if(ch=='"')return;
                if(ch<32)throw new IOException("Geo source raw control");
                if(key){
                    // Generated schema field names are literal ASCII. Refuse
                    // escaped aliases too, so duplicate keys cannot be hidden.
                    if(at-begin>32||!(ch>='a'&&ch<='z'||ch=='_'))throw new IOException("Literal Geo source field name required");
                }else if(ch=='\\'){
                    if(at>=text.length())throw new IOException("Short Geo source string escape");char escape=text.charAt(at++);
                    if(escape=='u'){
                        int unit=hex();
                        if(unit>=0xd800&&unit<=0xdbff){
                            if(at>text.length()-2||text.charAt(at++)!='\\'||text.charAt(at++)!='u')throw new IOException("Geo source surrogate pair required");
                            int low=hex();if(low<0xdc00||low>0xdfff)throw new IOException("Geo source low surrogate required");
                        }else if(unit>=0xdc00&&unit<=0xdfff)throw new IOException("Unpaired Geo source surrogate");
                    }else if("\"\\/bfnrt".indexOf(escape)<0)throw new IOException("Invalid Geo source string escape");
                }else if(Character.isHighSurrogate(ch)){
                    if(at>=text.length()||!Character.isLowSurrogate(text.charAt(at++)))throw new IOException("Geo source raw surrogate pair required");
                }else if(Character.isLowSurrogate(ch))throw new IOException("Unpaired Geo source raw surrogate");
            }
            throw new IOException("Unterminated Geo source string");
        }
    }
}
