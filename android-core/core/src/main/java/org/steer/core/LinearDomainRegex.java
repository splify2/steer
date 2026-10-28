package org.steer.core;

import java.util.*;

/** Independent bounded Thompson-NFA matcher for ASCII domain patterns. No Java
 * backtracking regex, resolver, native dependency or captured group contents.
 * Supports the RE2 domain subset: alternation/groups, classes/Perl ASCII classes,
 * anchors/boundaries, i/m/s/U flags, lazy/ordinary repetition and bounded counts.
 * Unicode properties, named captures, lookarounds, backreferences, octal and quoted blocks REFUSE
 * at preparation; they never become a wildcard or a silently missing condition.
 * Only normalized nonempty ASCII hostnames (<=253 chars) are matched. Flags m/s/U
 * cannot change a hostname's no-newline boolean result. Public admission is OFF. */
public final class LinearDomainRegex {
    private static final int CHAR=0,SPLIT=1,EMPTY=2,MATCH=3,START=4,END=5,BOUNDARY=6,NOT_BOUNDARY=7;
    private static final int SEQ=8,ALT=9,REPEAT=10,FLAGS=11,MAX_STATES=512;
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("Unsupported/bounded domain regex");}
    private static final class Node {
        final int kind;final BitSet chars;final List<Node> children;final int min,max;
        Node(int kind,BitSet chars,List<Node> children,int min,int max){this.kind=kind;this.chars=chars;this.children=children;this.min=min;this.max=max;}
    }
    private static final class State {
        final int kind;final BitSet chars;int next=-1,other=-1;
        State(int kind,BitSet chars){this.kind=kind;this.chars=chars;}
    }
    private static final class Fragment {
        final int start;final List<Integer> ends;
        Fragment(int start,List<Integer> ends){this.start=start;this.ends=ends;}
    }
    private final State[] states;private final int start;
    private LinearDomainRegex(State[] states,int start){this.states=states;this.start=start;}
    public int stateCount(){return states.length;}
    public static LinearDomainRegex compile(String pattern){
        if(pattern==null||pattern.length()>1024)throw invalid();
        for(int at=0;at<pattern.length();at++)if(pattern.charAt(at)>127)throw invalid();
        Parser parser=new Parser(pattern);Node root=parser.alternative();
        if(parser.at!=pattern.length())throw invalid();
        Compiler compiler=new Compiler();Fragment result=compiler.build(root);
        int accept=compiler.add(MATCH,null);compiler.patch(result.ends,accept);
        return new LinearDomainRegex(compiler.states.toArray(new State[0]),result.start);
    }
    private static boolean word(int value){return value=='_'||value>='a'&&value<='z'||value>='A'&&value<='Z'||value>='0'&&value<='9';}
    /** Linear in hostname length * bounded NFA states, including failed matches. */
    public boolean matches(String name){
        if(name==null||name.isEmpty()||name.length()>253)return false;
        for(int at=0;at<name.length();at++){
            char value=name.charAt(at);if(!word(value)&&value!='.'&&value!='-')return false;
        }
        BitSet active=new BitSet(states.length),next=new BitSet(states.length);
        int[] seen=new int[states.length],stack=new int[states.length];
        if(expand(start,0,name,active,seen,1,stack))return true;
        for(int at=0;at<name.length();at++){
            next.clear();int stamp=at+2,value=name.charAt(at);
            for(int state=active.nextSetBit(0);state>=0;state=active.nextSetBit(state+1))
                if(states[state].chars.get(value)&&expand(states[state].next,at+1,name,next,seen,stamp,stack))return true;
            if(expand(start,at+1,name,next,seen,stamp,stack))return true;
            BitSet swap=active;active=next;next=swap;
        }
        return false;
    }
    private boolean expand(int seed,int position,String name,BitSet active,int[] seen,int stamp,int[] stack){
        if(seed<0||seen[seed]==stamp)return false;int count=0;stack[count++]=seed;seen[seed]=stamp;
        while(count!=0){
            int index=stack[--count];State state=states[index];
            if(state.kind==MATCH)return true;
            if(state.kind==CHAR){active.set(index);continue;}
            if(state.kind==START&&position!=0||state.kind==END&&position!=name.length())continue;
            if(state.kind==BOUNDARY||state.kind==NOT_BOUNDARY){
                boolean boundary=word(position==0?-1:name.charAt(position-1))!=word(position==name.length()?-1:name.charAt(position));
                if(boundary!=(state.kind==BOUNDARY))continue;
            }
            if(state.next>=0&&seen[state.next]!=stamp){seen[state.next]=stamp;stack[count++]=state.next;}
            if(state.kind==SPLIT&&state.other>=0&&seen[state.other]!=stamp){seen[state.other]=stamp;stack[count++]=state.other;}
        }
        return false;
    }
    private static final class Compiler {
        final List<State> states=new ArrayList<>();
        int add(int kind,BitSet chars){if(states.size()>=MAX_STATES)throw invalid();states.add(new State(kind,chars));return states.size()-1;}
        void patch(List<Integer> ends,int target){
            for(int value:ends){State state=states.get(value>>>1);if((value&1)==0){if(state.next!=-1)throw invalid();state.next=target;}
                else{if(state.other!=-1)throw invalid();state.other=target;}}
        }
        Fragment one(int kind,BitSet chars){int index=add(kind,chars);return new Fragment(index,new ArrayList<>(Collections.singletonList(index<<1)));}
        Fragment join(Fragment first,Fragment second){if(first==null)return second;patch(first.ends,second.start);return new Fragment(first.start,second.ends);}
        Fragment optional(Node child,boolean looping){
            Fragment part=build(child);int split=add(SPLIT,null);states.get(split).next=part.start;
            List<Integer> ends=new ArrayList<>();ends.add((split<<1)|1);
            if(looping)patch(part.ends,split);else ends.addAll(part.ends);
            return new Fragment(split,ends);
        }
        Fragment build(Node node){
            if(node.kind==FLAGS)return one(EMPTY,null);
            if(node.kind==SEQ){Fragment result=null;for(Node child:node.children)result=join(result,build(child));return result==null?one(EMPTY,null):result;}
            if(node.kind==ALT){
                Fragment result=null;
                for(Node child:node.children){Fragment part=build(child);if(result==null){result=part;continue;}
                    int split=add(SPLIT,null);states.get(split).next=result.start;states.get(split).other=part.start;
                    List<Integer> ends=new ArrayList<>(result.ends);ends.addAll(part.ends);result=new Fragment(split,ends);}
                return result;
            }
            if(node.kind==REPEAT){
                Fragment result=null;Node child=node.children.get(0);
                for(int at=0;at<node.min;at++)result=join(result,build(child));
                if(node.max<0)result=join(result,optional(child,true));
                else for(int at=node.min;at<node.max;at++)result=join(result,optional(child,false));
                return result==null?one(EMPTY,null):result;
            }
            return one(node.kind,node.chars);
        }
    }
    private static final class Parser {
        final String source;int at,nodes,depth;boolean insensitive;
        Parser(String source){this.source=source;}
        boolean take(char value){if(at<source.length()&&source.charAt(at)==value){at++;return true;}return false;}
        Node node(int kind,BitSet chars,List<Node> children,int min,int max){if(++nodes>512)throw invalid();return new Node(kind,chars,children,min,max);}
        Node leaf(int kind){return node(kind,null,null,0,0);}
        Node character(BitSet chars){return node(CHAR,fold(chars),null,0,0);}
        BitSet fold(BitSet chars){if(insensitive)for(int value='A';value<='Z';value++)if(chars.get(value)||chars.get(value+32)){chars.set(value);chars.set(value+32);}return chars;}
        BitSet single(int value){BitSet chars=new BitSet(128);chars.set(value);return chars;}
        Node alternative(){
            List<Node> children=new ArrayList<>();children.add(sequence());while(take('|'))children.add(sequence());
            return children.size()==1?children.get(0):node(ALT,null,children,0,0);
        }
        Node sequence(){
            List<Node> children=new ArrayList<>();
            while(at<source.length()&&source.charAt(at)!=')'&&source.charAt(at)!='|')children.add(repetition());
            return children.size()==1?children.get(0):node(SEQ,null,children,0,0);
        }
        int count(){int begin=at,value=0;while(at<source.length()&&source.charAt(at)>='0'&&source.charAt(at)<='9'){
            value=value*10+source.charAt(at++)-'0';if(value>256)throw invalid();}
            if(at==begin)throw invalid();return value;}
        Node repetition(){
            Node atom=atom();int min,max;boolean repeat=true;
            if(take('*')){min=0;max=-1;}else if(take('+')){min=1;max=-1;}else if(take('?')){min=0;max=1;}
            else if(take('{')){min=count();max=min;if(take(','))max=at<source.length()&&source.charAt(at)=='}'?-1:count();
                if(!take('}')||max>=0&&max<min)throw invalid();}
            else{repeat=false;min=max=0;}
            if(!repeat)return atom;
            if(atom.kind==START||atom.kind==END||atom.kind==BOUNDARY||atom.kind==NOT_BOUNDARY||atom.kind==FLAGS)throw invalid();
            take('?'); // Greediness cannot affect a boolean match; no backtracking.
            return node(REPEAT,null,Collections.singletonList(atom),min,max);
        }
        Node atom(){
            if(at==source.length())throw invalid();char value=source.charAt(at++);
            if(value=='('){
                if(++depth>16)throw invalid();boolean before=insensitive;
                if(take('?')&&!take(':')){
                    boolean enabled=true,flag=false,afterMinus=false;
                    while(at<source.length()){
                        char next=source.charAt(at);if(next=='-'){if(!enabled)throw invalid();enabled=false;afterMinus=false;at++;continue;}
                        if(next!='i'&&next!='m'&&next!='s'&&next!='U')break;
                        flag=true;if(!enabled)afterMinus=true;if(next=='i')insensitive=enabled;at++;
                    }
                    if(!flag||!enabled&&!afterMinus)throw invalid();
                    if(take(')')){depth--;return leaf(FLAGS);}
                    if(!take(':'))throw invalid();
                }
                Node result=alternative();if(!take(')'))throw invalid();insensitive=before;depth--;return result;
            }
            if(value=='[')return character(charClass());
            if(value=='.'){BitSet chars=new BitSet(128);chars.set(0,128);chars.clear('\n');return character(chars);}
            if(value=='^')return leaf(START);if(value=='$')return leaf(END);
            if(value=='\\'){
                if(take('A'))return leaf(START);if(take('z'))return leaf(END);
                if(take('b'))return leaf(BOUNDARY);if(take('B'))return leaf(NOT_BOUNDARY);
                return character(escape());
            }
            if("*+?{}]".indexOf(value)>=0)throw invalid();return character(single(value));
        }
        BitSet charClass(){
            boolean negative=take('^');BitSet chars=new BitSet(128);boolean first=true,closed=false;
            while(at<source.length()){
                if(source.charAt(at)==']'&&!first){at++;closed=true;break;}
                BitSet part=classPart();first=false;
                if(at+1<source.length()&&source.charAt(at)=='-'&&source.charAt(at+1)!=']'){
                    at++;BitSet end=classPart();if(part.cardinality()!=1||end.cardinality()!=1)throw invalid();
                    int from=part.nextSetBit(0),to=end.nextSetBit(0);if(to<from)throw invalid();chars.set(from,to+1);
                }else chars.or(part);
            }
            if(!closed)throw invalid();fold(chars);if(negative)chars.flip(0,128);return chars;
        }
        BitSet classPart(){if(at==source.length())throw invalid();char value=source.charAt(at++);
            if(value=='['){
                if(!take(':'))return single('[');boolean negative=take('^');int begin=at;
                while(at<source.length()&&source.charAt(at)>='a'&&source.charAt(at)<='z')at++;
                String name=source.substring(begin,at);if(!take(':')||!take(']'))throw invalid();
                if(!Arrays.asList("alnum","alpha","ascii","blank","cntrl","digit","graph","lower","print","punct","space","upper","word","xdigit").contains(name))throw invalid();
                BitSet chars=new BitSet(128);
                for(int c=0;c<128;c++){
                    boolean digit=c>='0'&&c<='9',lower=c>='a'&&c<='z',upper=c>='A'&&c<='Z',letter=lower||upper;
                    boolean match=name.equals("ascii")||name.equals("alnum")&&(letter||digit)||name.equals("alpha")&&letter||
                        name.equals("blank")&&(c==' '||c=='\t')||name.equals("cntrl")&&(c<32||c==127)||name.equals("digit")&&digit||
                        name.equals("graph")&&c>=33&&c<=126||name.equals("lower")&&lower||name.equals("print")&&c>=32&&c<=126||
                        name.equals("punct")&&c>=33&&c<=126&&!letter&&!digit||name.equals("space")&&(c==' '||c>=9&&c<=13)||
                        name.equals("upper")&&upper||name.equals("word")&&word(c)||name.equals("xdigit")&&(digit||c>='a'&&c<='f'||c>='A'&&c<='F');
                    if(match)chars.set(c);
                }
                fold(chars);if(negative)chars.flip(0,128);return chars;
            }
            return value=='\\'?escape():single(value);}
        BitSet escape(){
            if(at==source.length())throw invalid();char value=source.charAt(at++);BitSet chars=new BitSet(128);
            char lower=Character.toLowerCase(value);
            if(lower=='d'||lower=='w'||lower=='s'){
                if(lower=='d'||lower=='w')chars.set('0','9'+1);
                if(lower=='w'){chars.set('A','Z'+1);chars.set('a','z'+1);chars.set('_');}
                if(lower=='s'){chars.set('\t');chars.set('\n');chars.set('\f');chars.set('\r');chars.set(' ');}
                if(value!=lower)chars.flip(0,128);return chars;
            }
            if(value=='x'){
                if(at+2>source.length())throw invalid();int high=Character.digit(source.charAt(at++),16),low=Character.digit(source.charAt(at++),16);
                if(high<0||low<0||high*16+low>127)throw invalid();return single(high*16+low);
            }
            String controls="afnrtv";int index=controls.indexOf(value);if(index>=0)return single(new int[]{7,12,10,13,9,11}[index]);
            if(Character.isLetterOrDigit(value))throw invalid();return single(value);
        }
    }
    @Override public String toString(){return "LinearDomainRegex(redacted)";}
}
