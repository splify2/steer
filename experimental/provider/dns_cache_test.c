#include "dns_cache.h"
#include "dns_doh.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void){struct steer_dns_cache *c=steer_dns_cache_create(2),*copy=steer_dns_cache_create(2);struct steer_dns_cache_key k={{1},"example.com",1};struct steer_dns_answer a={0},out;uint8_t *snapshot,q[4096],http[12288],body[4096];size_t n,used,size,bodylen;char host[254];const char *head="HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 29\r\n\r\n";
    assert(c&&copy);a.ttl=100;a.count=1;a.addresses[0].family=4;a.addresses[0].bytes[0]=127;a.addresses[0].bytes[3]=1;a.addresses[0].ttl=100;assert(!steer_dns_cache_put(c,&k,&a,1000));assert(steer_dns_cache_get(c,&k,2000,&out)&&out.ttl==99);assert(steer_dns_cache_reverse(c,k.identity,4,a.addresses[0].bytes,2000,host)&&!strcmp(host,k.name));
    snapshot=malloc(steer_dns_cache_snapshot_max(c));assert(snapshot);assert(!steer_dns_cache_export(c,2000,100,snapshot,steer_dns_cache_snapshot_max(c),&used));assert(!steer_dns_cache_import(copy,k.identity,5000,110,snapshot,used));assert(steer_dns_cache_get(copy,&k,5000,&out)&&out.ttl==89);snapshot[4]=1;assert(steer_dns_cache_import(copy,k.identity,5000,110,snapshot,used)==-1);assert(steer_dns_cache_get(copy,&k,5000,&out));snapshot[4]=0;k.identity[0]=2;assert(!steer_dns_cache_import(copy,k.identity,5000,110,snapshot,used));assert(!steer_dns_cache_get(copy,&k,5000,&out));free(snapshot);steer_dns_cache_free(c);steer_dns_cache_free(copy);
    assert(!steer_dns_query("example.com",1,42,q,sizeof(q),&n)&&n==29);assert(!steer_dns_doh_request("resolver.example","/dns-query",q,n,http,sizeof(http),&size));assert(size>n&&!memcmp(http+size-n,q,n));assert(steer_dns_doh_request("bad\r\nHost: injected","/dns-query",q,n,http,sizeof(http),&size));
    size=strlen(head);memcpy(http,head,size);memcpy(http+size,q,n);size+=n;assert(steer_dns_doh_response(http,size-1,body,sizeof(body),&bodylen)==0);assert(steer_dns_doh_response(http,size,body,sizeof(body),&bodylen)==1&&bodylen==n&&!memcmp(q,body,n));http[size++]=0;assert(steer_dns_doh_response(http,size,body,sizeof(body),&bodylen)==-1);
    head="HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n1d\r\n";size=strlen(head);memcpy(http,head,size);memcpy(http+size,q,n);size+=n;memcpy(http+size,"\r\n0\r\n\r\n",7);size+=7;assert(steer_dns_doh_response(http,size,body,sizeof(body),&bodylen)==1&&bodylen==n&&!memcmp(q,body,n));
    puts("dns cache/DoH codec: ok");return 0;
}
