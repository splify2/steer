#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "tls13.h"
#include "tls13_offered.h"

static void u16(unsigned char *p, size_t n) { p[0] = (unsigned char)(n >> 8); p[1] = (unsigned char)n; }
static size_t hello(unsigned char *p) {
    memset(p, 0, 256); p[0]=1; p[4]=3; p[5]=3; p[38]=2; p[39]=42; p[40]=43;
    size_t at=41; u16(p+at,2); at+=2; u16(p+at,0x1301); at+=2;
    p[at++]=1; p[at++]=0; size_t ext=at; at+=2;
    const unsigned char extensions[]={
        0,43,0,3,2,3,4,
        0,51,0,7,0,5,0,29,0,1,42,
        0,13,0,4,0,2,8,7,
        0,16,0,14,0,12,2,'h','2',8,'h','t','t','p','/','1','.','1'};
    memcpy(p+at,extensions,sizeof(extensions));at+=sizeof(extensions);
    u16(p+ext,at-ext-2);p[3]=(unsigned char)(at-4);return at;
}
static size_t server(unsigned char *p) {
    memset(p,0,256);p[0]=2;p[4]=3;p[5]=3;p[38]=2;p[39]=42;p[40]=43;
    u16(p+41,0x1301);p[43]=0;
    const unsigned char ext[]={0,43,0,2,3,4,0,51,0,5,0,29,0,1,99};
    u16(p+44,sizeof(ext));memcpy(p+46,ext,sizeof(ext));p[3]=(unsigned char)(42+sizeof(ext));
    return 46+sizeof(ext);
}
int main(void) {
    unsigned char ch[256],sh[256],copy[256];struct tls13_offered offered;
    size_t cn=hello(ch),sn=server(sh);assert(!parse_client_offer(ch,cn,&offered));
    assert(!match_server_offer(&offered,sh,sn));
    for(size_t cut=0;cut<cn;cut++)assert(parse_client_offer(ch,cut,&offered)==TLS13_EBADREC);
    assert(!parse_client_offer(ch,cn,&offered));
    memcpy(copy,sh,sn);copy[39]^=1;assert(match_server_offer(&offered,copy,sn)==TLS13_EBADREC);
    memcpy(copy,sh,sn);u16(copy+41,0x1302);assert(match_server_offer(&offered,copy,sn)==TLS13_EBADREC);
    memcpy(copy,sh,sn);copy[57]=23;assert(match_server_offer(&offered,copy,sn)==TLS13_EBADREC);
    assert(offer_has_alpn(&offered,(const unsigned char *)"h2",2));
    assert(offer_has_alpn(&offered,(const unsigned char *)"http/1.1",8));
    assert(!offer_has_alpn(&offered,(const unsigned char *)"h2\0junk",7));
    assert(!offer_has_alpn(&offered,(const unsigned char *)"h",1));
    assert(offer_has_u16(offered.signatures,offered.signatures_n,0x0807));
    assert(!offer_has_u16(offered.signatures,offered.signatures_n,0x0401));
    memcpy(copy,ch,cn);copy[46]=1;assert(parse_client_offer(copy,cn,&offered)==TLS13_EBADREC);
    memcpy(copy,ch,cn);copy[cn-13]=0;assert(parse_client_offer(copy,cn,&offered)==TLS13_EBADREC);
    puts("ClientHello offered negotiation views: PASS");return 0;
}
