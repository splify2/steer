/* Private bounded HPACK status scanner. Included only by h2.c after digits_huff.
 * Existing ctl[64] is exclusive scratch while a contiguous header block is open.
 * memcpy avoids assuming alignment of that legacy byte-array ABI storage. */
struct hp_status_state {
    uint32_t integer, left, total;
    unsigned char phase,target,shift,name,huffman,string_name,captured,seen;
    unsigned char capture[16];
};
_Static_assert(sizeof(struct hp_status_state)<=64,"HPACK state fits legacy scratch");
enum {HP_FIELD,HP_NAME_HEAD,HP_VALUE_HEAD,HP_STRING,HP_INTEGER};
enum {HP_INDEX=1,HP_NAME_INDEX,HP_NAME_LENGTH,HP_VALUE_LENGTH,HP_TABLE_SIZE};
static int hp_value(struct h2 *h,struct hp_status_state *s) {
    int value=-1;
    if(s->name==1) {
        if(s->huffman)value=status_huff(s->capture,s->captured);
        else if(s->captured==3 && s->capture[0]>='1' && s->capture[0]<='5' &&
                s->capture[1]>='0' && s->capture[1]<='9' && s->capture[2]>='0' && s->capture[2]<='9')
            value=(s->capture[0]-'0')*100+(s->capture[1]-'0')*10+s->capture[2]-'0';
        if(value<100||value>599 || (h->frame_peeked & (HP_HAVE|HP_TRAILER)))return H2_EPROTO;
        h->frame_peeked|=HP_HAVE;
        if(h->frame_ours)h->status=value;
        else if(value>=200&&value!=200)h->old_status=value;
    } else if(s->name==2) {
        if(!(h->frame_peeked & HP_END))return H2_EPROTO;
        if(s->huffman) {
            value=digits_huff(s->capture,s->captured,1);
            if(value<0)value=digits_huff(s->capture,s->captured,2);
        } else if(s->captured==1 && s->capture[0]>='0' && s->capture[0]<='9')value=s->capture[0]-'0';
        else if(s->captured==2 && s->capture[0]=='1' && s->capture[1]>='0' && s->capture[1]<='6')value=10+s->capture[1]-'0';
        if(value!=0 || (h->frame_peeked & H2_GRPC_STATUS_OK)) {
            h->frame_peeked|=H2_GRPC_STATUS_ERROR;return H2_EPROTO;
        }
        h->frame_peeked|=H2_GRPC_STATUS_OK;
    }
    s->seen=1;s->name=0;s->phase=HP_FIELD;return 0;
}
static int hp_string_done(struct h2 *h,struct hp_status_state *s) {
    if(s->string_name) {
        static const unsigned char sh[]={0xb8,0x84,0x8d,0x36,0xa3};
        static const unsigned char gh[]={0x9a,0xca,0xc8,0xb2,0x12,0x34,0xda,0x8f};
        s->name=0;
        if((!s->huffman && s->captured==7 && !memcmp(s->capture,":status",7)) ||
           (s->huffman && s->captured==sizeof(sh) && !memcmp(s->capture,sh,sizeof(sh))))s->name=1;
        if((!s->huffman && s->captured==11 && !memcmp(s->capture,"grpc-status",11)) ||
           (s->huffman && s->captured==sizeof(gh) && !memcmp(s->capture,gh,sizeof(gh))))s->name=2;
        if(!(h->frame_peeked & (HP_HAVE|HP_TRAILER)) && s->name!=1)return H2_EPROTO;
        if(!s->huffman && s->captured && s->capture[0]==':' && s->name!=1)return H2_EPROTO;
        s->phase=HP_VALUE_HEAD;return 0;
    }
    return hp_value(h,s);
}
static int hp_integer_done(struct h2 *h,struct hp_status_state *s) {
    uint32_t value=s->integer;
    switch(s->target) {
    case HP_TABLE_SIZE:
        if(value || s->seen)return H2_EPROTO;
        s->phase=HP_FIELD;return 0;
    case HP_INDEX:
        if(!value||value>61||value<8)return H2_EPROTO;
        if(value<=14) {
            static const int values[]={200,204,206,304,400,404,500};
            int status=values[value-8];
            if(h->frame_peeked & (HP_HAVE|HP_TRAILER))return H2_EPROTO;
            h->frame_peeked|=HP_HAVE;
            if(h->frame_ours)h->status=status;
            else if(status!=200)h->old_status=status;
        } else if(!(h->frame_peeked & (HP_HAVE|HP_TRAILER)))return H2_EPROTO;
        s->seen=1;s->phase=HP_FIELD;return 0;
    case HP_NAME_INDEX:
        if(value>61 || (value && value<8))return H2_EPROTO;
        if(!value){s->phase=HP_NAME_HEAD;return 0;}
        s->name=value<=14?1:0;
        if(!s->name && !(h->frame_peeked & (HP_HAVE|HP_TRAILER)))return H2_EPROTO;
        s->phase=HP_VALUE_HEAD;return 0;
    case HP_NAME_LENGTH:
    case HP_VALUE_LENGTH:
        if(value>65536)return H2_ETOOBIG;
        s->left=value;s->captured=0;s->string_name=s->target==HP_NAME_LENGTH;
        s->phase=HP_STRING;
        if(!value) {
            if(s->string_name)return H2_EPROTO;
            return hp_string_done(h,s);
        }
        return 0;
    default:return H2_EPROTO;
    }
}
static int hp_integer_start(struct h2 *h,struct hp_status_state *s,unsigned char byte,unsigned mask,unsigned target) {
    s->target=(unsigned char)target;s->integer=byte & mask;s->shift=0;
    if(s->integer==mask){s->phase=HP_INTEGER;return 0;}
    return hp_integer_done(h,s);
}
static int status_append(struct h2 *h,const unsigned char *p,size_t n) {
    struct hp_status_state s={0};
    if(h->ctl_n)memcpy(&s,h->ctl,sizeof(s));
    while(n--) {
        unsigned char byte=*p++;int rc=0;
        if(++s.total>65536)return H2_ETOOBIG;
        if(!(h->frame_peeked & (HP_HAVE|HP_TRAILER)) && s.total>64)return H2_ETOOBIG;
        switch(s.phase) {
        case HP_FIELD:
            if(byte & 0x80)rc=hp_integer_start(h,&s,byte,127,HP_INDEX);
            else if((byte & 0xe0)==0x20)rc=hp_integer_start(h,&s,byte,31,HP_TABLE_SIZE);
            else rc=hp_integer_start(h,&s,byte,byte & 0x40?63:15,HP_NAME_INDEX);
            break;
        case HP_NAME_HEAD:
        case HP_VALUE_HEAD:
            s.huffman=(byte & 0x80)!=0;
            rc=hp_integer_start(h,&s,byte,127,s.phase==HP_NAME_HEAD?HP_NAME_LENGTH:HP_VALUE_LENGTH);
            break;
        case HP_INTEGER: {
            uint32_t digit=byte & 127;
            if(s.shift>28 || (s.shift==28 && digit>15) || (digit<<s.shift)>UINT32_MAX-s.integer)return H2_EPROTO;
            s.integer+=digit<<s.shift;
            if(byte & 0x80){if(s.shift==28)return H2_EPROTO;s.shift=(unsigned char)(s.shift+7);}
            else rc=hp_integer_done(h,&s);
            break;
        }
        case HP_STRING:
            if(s.captured<sizeof(s.capture))s.capture[s.captured++]=byte;
            if(!--s.left)rc=hp_string_done(h,&s);
            break;
        default:return H2_EPROTO;
        }
        if(rc)return rc;
    }
    memcpy(h->ctl,&s,sizeof(s));h->ctl_n=1;return 0;
}
static int status_complete(const struct h2 *h) {
    struct hp_status_state s={0};if(h->ctl_n)memcpy(&s,h->ctl,sizeof(s));
    return s.phase==HP_FIELD;
}
