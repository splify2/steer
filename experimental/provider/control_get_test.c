#include "control_get.h"
#include "prototype_config.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void){
    const size_t max=STEER_PROTOTYPE_CONFIG_MAX_BYTES;
    char *doc=malloc(max),*out=malloc(max+2048+2);
    assert(doc&&out);
    memset(doc,'a',max);doc[0]='"';doc[max-1]='"';
    memset(out,0x5a,max+2048+2);
    size_t length=0;
    assert(steer_control_get_frame(out+1,max+2048,&length,doc,max,UINT64_MAX,UINT64_MAX,1,1,1,0));
    assert(length>max+128&&length<max+2048);
    assert(out[0]=='Z'&&out[max+2048+1]=='Z');
    char *newline=memchr(out+1,'\n',length);assert(newline);
    size_t body_length=0;assert(sscanf(out+1,"OK %zu",&body_length)==1);
    assert(body_length==length-(size_t)(newline-(out+1))-1);
    assert(!memcmp(out+length-max,doc,max)&&out[length]=='}');
    size_t untouched=123;
    memset(out,0x5a,max+2048+2);
    assert(!steer_control_get_frame(out+1,length-1,&untouched,doc,max,UINT64_MAX,UINT64_MAX,1,1,1,0));
    assert(untouched==123&&out[0]=='Z'&&out[length]=='Z');
    assert(steer_control_get_frame(out+1,length,&untouched,doc,max,UINT64_MAX,UINT64_MAX,1,1,1,0));
    assert(untouched==length&&out[length+1]=='Z');
    assert(!steer_control_get_frame(out+1,max+2048,&untouched,doc,SIZE_MAX,1,1,0,0,1,0));
    const char expected[]="OK 76\n{\"revision\":1,\"persistence\":true,\"durability_uncertain\":false,\"document\":{}}";
    assert(steer_control_get_frame(out+1,max+2048,&length,"{}",2,1,1,0,0,1,0));
    assert(length==sizeof(expected)-1&&!memcmp(out+1,expected,length));
    free(out);free(doc);
    puts("GET serializer bounds and legacy frame PASS");
    return 0;
}
