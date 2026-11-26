#ifndef STEER_PROTOTYPE_CONTROL_GET_H
#define STEER_PROTOTYPE_CONTROL_GET_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Writes the complete control frame into out, never through request storage.
 * The document and out must not overlap. Returns zero if it cannot fit. */
static int steer_control_get_frame(char *out,size_t capacity,size_t *written,
    const char *document,size_t document_length,uint64_t revision,uint64_t runtime,
    int split,int fenced,int persistence,int uncertain)
{
    char prefix[256],header[64];
    int n;
    if(!out||!written||!document)return 0;
    if(split)
        n=snprintf(prefix,sizeof prefix,"{\"revision\":%llu,\"runtimeGeneration\":%llu,\"splitFenced\":%s,\"persistence\":%s,\"durability_uncertain\":%s,\"document\":",
            (unsigned long long)revision,(unsigned long long)runtime,fenced?"true":"false",
            persistence?"true":"false",uncertain?"true":"false");
    else
        n=snprintf(prefix,sizeof prefix,"{\"revision\":%llu,\"persistence\":%s,\"durability_uncertain\":%s,\"document\":",
            (unsigned long long)revision,persistence?"true":"false",uncertain?"true":"false");
    if(n<0||(size_t)n>=sizeof prefix)return 0;
    size_t prefix_length=(size_t)n;
    if(document_length>SIZE_MAX-prefix_length-1)return 0;
    size_t body_length=prefix_length+document_length+1;
    n=snprintf(header,sizeof header,"OK %zu\n",body_length);
    if(n<0||(size_t)n>=sizeof header)return 0;
    size_t header_length=(size_t)n,used=0;
    if(header_length>capacity-used)return 0;
    memcpy(out+used,header,header_length);used+=header_length;
    if(prefix_length>capacity-used)return 0;
    memcpy(out+used,prefix,prefix_length);used+=prefix_length;
    if(document_length>capacity-used)return 0;
    memcpy(out+used,document,document_length);used+=document_length;
    if(capacity-used<1)return 0;
    out[used++]='}';
    *written=used;
    return 1;
}
#endif
