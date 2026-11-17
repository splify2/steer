#include "dns_wire.h"
#include <string.h>
#include <limits.h>
static uint16_t u16(const uint8_t *p){return (uint16_t)((p[0]<<8)|p[1]);}
static uint32_t u32(const uint8_t *p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)(n>>8);p[1]=(uint8_t)n;}
static int name(const uint8_t *p,size_t n,size_t *pos,char out[254]){
    size_t at=*pos,end=0,used=0;unsigned hops=0;
    for(;;){unsigned len,i;if(at>=n||++hops>128)return -1;len=p[at++];
        if((len&192)==192){size_t target;if(at>=n)return -1;target=((len&63)<<8)|p[at++];if(!end)end=at;if(target>=n)return -1;at=target;continue;}
        if(len&192||len>63||at+len>n)return -1;
        if(!len){if(!end)end=at;break;}
        if(used){if(used>=253)return -1;out[used++]='.';}
        if(used+len>253)return -1;
        for(i=0;i<len;i++){unsigned c=p[at++];if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'))return -1;out[used++]=(char)(c>='A'&&c<='Z'?c+32:c);}
    }
    out[used]=0;*pos=end;return 0;
}
int steer_dns_question_read(const uint8_t *p,size_t n,struct steer_dns_question *q){
    size_t pos=12;if(!p||!q||n<12||n>STEER_DNS_PACKET_MAX||u16(p+4)!=1||name(p,n,&pos,q->name)||!q->name[0]||pos+4>n||u16(p+pos+2)!=1)return -1;
    q->id=u16(p);q->type=u16(p+pos);q->end=pos+4;return 0;
}
int steer_dns_query(const char *host,uint16_t type,uint16_t id,uint8_t *p,size_t cap,size_t *out){
    size_t at=12,start=0,i,len;if(out)*out=0;if(!host||!p||!out||cap<17)return -1;len=strlen(host);if(len&&host[len-1]=='.')len--;if(!len||len>253)return -1;
    memset(p,0,12);put16(p,id);p[2]=1;p[5]=1;
    for(i=0;i<=len;i++)if(i==len||host[i]=='.'){size_t j,l=i-start;if(!l||l>63||at+1+l+5>cap)return -1;p[at++]=(uint8_t)l;for(j=start;j<i;j++){unsigned c=(unsigned char)host[j];if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'))return -1;p[at++]=(uint8_t)c;}start=i+1;}
    p[at++]=0;put16(p+at,type);put16(p+at+2,1);*out=at+4;return 0;
}
struct rr {char owner[254],alias[254];size_t data;uint32_t ttl;uint16_t type,len,cls;};
static int record(const uint8_t *p,size_t n,size_t *at,struct rr *r){size_t end,t;if(name(p,n,at,r->owner)||*at+10>n)return -1;r->type=u16(p+*at);r->cls=u16(p+*at+2);r->ttl=u32(p+*at+4);r->len=u16(p+*at+8);r->data=*at+10;end=r->data+r->len;if(end>n)return -1;r->alias[0]=0;if(r->type==5){t=r->data;if(name(p,n,&t,r->alias)||t!=end)return -1;}*at=end;return 0;}
int steer_dns_answer_read(const uint8_t *p,size_t n,const struct steer_dns_question *expected,int ipv4,struct steer_dns_answer *out){
    struct steer_dns_question q;struct rr r;size_t at;uint32_t count,i,h;char target[254];uint32_t chain_ttl=UINT_MAX;
    if(!out||!expected||steer_dns_question_read(p,n,&q)||q.id!=expected->id||q.type!=expected->type||strcmp(q.name,expected->name)||(p[2]&0xfa)!=0x80)return -1;
    count=(uint32_t)u16(p+6)+u16(p+8)+u16(p+10);at=q.end;for(i=0;i<count;i++)if(record(p,n,&at,&r))return -1;if(at!=n)return -1;
    memset(out,0,sizeof(*out));out->rcode=p[3]&15;out->ttl=UINT_MAX;strcpy(target,q.name);
    for(h=0;h<16;h++){char next[254]="";at=q.end;for(i=0;i<u16(p+6);i++){if(record(p,n,&at,&r))return -1;if(r.cls==1&&r.type==5&&!strcmp(r.owner,target)){if(!r.alias[0]||!strcmp(r.alias,target)||(next[0]&&strcmp(next,r.alias)))return -1;strcpy(next,r.alias);if(r.ttl<chain_ttl)chain_ttl=r.ttl;}}if(!next[0])break;strcpy(target,next);}if(h==16)return -1;
    at=q.end;for(i=0;i<u16(p+6);i++){struct steer_dns_address *a;if(record(p,n,&at,&r))return -1;if(r.cls!=1||strcmp(r.owner,target)||(r.type!=1&&r.type!=28))continue;if((r.type==1&&r.len!=4)||(r.type==28&&r.len!=16))return -1;if((ipv4&&r.type==28)||(q.type!=255&&q.type!=r.type))continue;if(out->count==STEER_DNS_ADDRESS_MAX)continue;a=&out->addresses[out->count++];a->family=r.type==1?4:6;memcpy(a->bytes,p+r.data,r.len);a->ttl=r.ttl<chain_ttl?r.ttl:chain_ttl;if(a->ttl<out->ttl)out->ttl=a->ttl;}
    if(!out->count)out->ttl=0;
    return 0;
}
int steer_dns_empty(const uint8_t *p,size_t n,uint8_t *out,size_t cap,size_t *size){struct steer_dns_question q;uint8_t tmp[STEER_DNS_PACKET_MAX];size_t len;if(size)*size=0;if(!out||!size||steer_dns_question_read(p,n,&q)||(p[2]&0xf8)||steer_dns_query(q.name,q.type,q.id,tmp,sizeof(tmp),&len)||len>cap)return -1;tmp[2]=(uint8_t)(0x80|(p[2]&1));tmp[3]=0x80;memcpy(out,tmp,len);*size=len;return 0;}
