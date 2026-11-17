#include "dns_doh.h"
#include <string.h>
#include <stdio.h>
static int lower(int c){return c>='A'&&c<='Z'?c+32:c;}
static int equal(const uint8_t *p,size_t n,const char *s){size_t i;if(strlen(s)!=n)return 0;for(i=0;i<n;i++)if(lower(p[i])!=s[i])return 0;return 1;}
static size_t line(const uint8_t *p,size_t n,size_t at){size_t i;for(i=at;i+1<n;i++)if(p[i]=='\r'&&p[i+1]=='\n')return i;return n;}
int steer_dns_doh_request(const char *host,const char *path,const uint8_t *q,size_t n,uint8_t *out,size_t cap,size_t *size){
    size_t i;int written;struct steer_dns_question question;if(size)*size=0;if(!host||!path||!out||!size||!host[0]||strlen(host)>255||path[0]!='/'||strlen(path)>1024||steer_dns_question_read(q,n,&question))return -1;
    for(i=0;host[i];i++){unsigned c=(unsigned char)host[i];if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='-'||c==':'||c=='['||c==']'))return -1;}
    for(i=0;path[i];i++)if((unsigned char)path[i]<33||(unsigned char)path[i]>126||path[i]=='#')return -1;
    written=snprintf((char *)out,cap,"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",path,host,n);
    if(written<0||(size_t)written>=cap||n>cap-(size_t)written)return -1;
    memcpy(out+written,q,n);*size=(size_t)written+n;return 0;
}
int steer_dns_doh_response(const uint8_t *p,size_t n,uint8_t *out,size_t cap,size_t *size){
    size_t at,end,length=0,total=0;int have_length=0,chunked=0,type=0;if(size)*size=0;if(!p||!out||!size||n>STEER_DNS_DOH_HTTP_MAX)return -1;
    end=line(p,n,0);if(end==n)return n>4096?-1:0;if(end!=12||memcmp(p,"HTTP/1.",7)||(p[7]!='0'&&p[7]!='1')||memcmp(p+8," 200",4)){
        /* Reason phrase is optional and otherwise ignored, status is exact. */
        if(end<12||memcmp(p,"HTTP/1.",7)||(p[7]!='0'&&p[7]!='1')||memcmp(p+8," 200",4)||(end>12&&p[12]!=' '))return -1;
    }
    at=end+2;for(;;){size_t colon,value,last,i;end=line(p,n,at);if(end==n)return n>4096?-1:0;if(end>4096)return -1;if(end==at){at=end+2;break;}if(p[at]==' '||p[at]=='\t')return -1;
        for(colon=at;colon<end&&p[colon]!=':';colon++){}if(colon==end||colon==at)return -1;
        for(i=at;i<colon;i++)if(!((p[i]>='a'&&p[i]<='z')||(p[i]>='A'&&p[i]<='Z')||(p[i]>='0'&&p[i]<='9')||p[i]=='-'))return -1;
        value=colon+1;while(value<end&&(p[value]==' '||p[value]=='\t'))value++;last=end;while(last>value&&(p[last-1]==' '||p[last-1]=='\t'))last--;
        for(i=value;i<last;i++)if((p[i]<32&&p[i]!='\t')||p[i]==127)return -1;
        if(equal(p+at,colon-at,"content-length")){if(have_length||value==last)return -1;have_length=1;for(i=value;i<last;i++){if(p[i]<'0'||p[i]>'9'||length>(STEER_DNS_PACKET_MAX-(p[i]-'0'))/10)return -1;length=length*10+(p[i]-'0');}}
        if(equal(p+at,colon-at,"transfer-encoding")){if(chunked||!equal(p+value,last-value,"chunked"))return -1;chunked=1;}
        if(equal(p+at,colon-at,"content-type")){if(type++||!equal(p+value,last-value,"application/dns-message"))return -1;}
        if(equal(p+at,colon-at,"content-encoding")&&!equal(p+value,last-value,"identity"))return -1;
        at=end+2;
    }
    if(type!=1||have_length==chunked)return -1;
    if(have_length){if(length<12||length>cap)return -1;if(n-at<length)return 0;if(n-at!=length)return -1;memcpy(out,p+at,length);*size=length;return 1;}
    for(;;){size_t chunk=0,i;end=line(p,n,at);if(end==n)return 0;if(end==at||end-at>8)return -1;for(i=at;i<end;i++){unsigned c=p[i],digit;if(c>='0'&&c<='9')digit=c-'0';else if(lower(c)>='a'&&lower(c)<='f')digit=(unsigned)(lower(c)-'a'+10);else return -1;if(chunk>(STEER_DNS_PACKET_MAX-digit)/16)return -1;chunk=chunk*16+digit;}at=end+2;
        if(!chunk){if(n-at<2)return 0;if(p[at]!='\r'||p[at+1]!='\n'||n-at!=2||total<12)return -1;*size=total;return 1;}
        if(chunk>cap-total||chunk>STEER_DNS_PACKET_MAX-total)return -1;
        if(n-at<chunk+2)return 0;
        if(p[at+chunk]!='\r'||p[at+chunk+1]!='\n')return -1;
        memcpy(out+total,p+at,chunk);total+=chunk;at+=chunk+2;
    }
}
