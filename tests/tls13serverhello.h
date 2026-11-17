/* Pure ServerHello boundary tests through a test-only source-link seam. */
int tls13_test_server_hello_validate(const unsigned char *,size_t);
static void server_hello_lengths(unsigned char *hello,size_t length) {
    size_t body=length-4,extensions=length-44;
    hello[1]=(unsigned char)(body>>16);hello[2]=(unsigned char)(body>>8);hello[3]=(unsigned char)body;
    hello[42]=(unsigned char)(extensions>>8);hello[43]=(unsigned char)extensions;
}
static size_t server_hello(unsigned char *hello,int hybrid) {
    memset(hello,0,1400);hello[0]=2;hello[4]=hello[5]=3;hello[39]=0x13;hello[40]=1;
    hello[45]=0x2b;hello[47]=2;hello[48]=3;hello[49]=4;
    size_t key_n=hybrid?SC_MLKEM768_CT+32:32;
    hello[51]=0x33;hello[52]=(unsigned char)((key_n+4)>>8);hello[53]=(unsigned char)(key_n+4);
    hello[54]=hybrid?0x11:0;hello[55]=hybrid?0xec:0x1d;hello[56]=(unsigned char)(key_n>>8);hello[57]=(unsigned char)key_n;
    size_t length=58+key_n;server_hello_lengths(hello,length);return length;
}
static void server_hello_bounds(void) {
    unsigned char hello[1400],copy[1400];size_t n=server_hello(hello,0);
    assert(!tls13_test_server_hello_validate(hello,n));
    assert(tls13_test_server_hello_validate(NULL,0)==TLS13_EBADREC);
    for(size_t cut=0;cut<n;cut++)assert(tls13_test_server_hello_validate(hello,cut)==TLS13_EBADREC);
    memcpy(copy,hello,n);copy[3]--;assert(tls13_test_server_hello_validate(copy,n)==TLS13_EBADREC);
    memcpy(copy,hello,n);copy[38]=32;server_hello_lengths(copy,44);assert(tls13_test_server_hello_validate(copy,44)==TLS13_EBADREC);
    memcpy(copy,hello,n);copy[38]=33;assert(tls13_test_server_hello_validate(copy,n)==TLS13_EBADREC);
    memcpy(copy,hello,n);copy[41]=1;assert(tls13_test_server_hello_validate(copy,n)==TLS13_EBADREC);
    memcpy(copy,hello,n);copy[49]=3;assert(tls13_test_server_hello_validate(copy,n)==TLS13_EBADREC);
    memcpy(copy,hello,44);memcpy(copy+44,hello+50,n-50);server_hello_lengths(copy,n-6);
    assert(tls13_test_server_hello_validate(copy,n-6)==TLS13_EBADREC);
    /* A valid key share cannot hide malformed trailing extension bytes. */
    for(size_t tail=1;tail<=3;tail++){
        memcpy(copy,hello,n);memset(copy+n,0,tail);server_hello_lengths(copy,n+tail);
        assert(tls13_test_server_hello_validate(copy,n+tail)==TLS13_EBADREC);
    }
    memcpy(copy,hello,n);copy[n]=0x12;copy[n+1]=0x34;copy[n+2]=0;copy[n+3]=1;
    server_hello_lengths(copy,n+4);assert(tls13_test_server_hello_validate(copy,n+4)==TLS13_EBADREC);
    copy[n+3]=0;assert(!tls13_test_server_hello_validate(copy,n+4));
    memcpy(copy+n+4,copy+n,4);server_hello_lengths(copy,n+8);
    assert(tls13_test_server_hello_validate(copy,n+8)==TLS13_EBADREC);
    memcpy(copy,hello,n);memcpy(copy+n,hello+50,n-50);server_hello_lengths(copy,2*n-50);
    assert(tls13_test_server_hello_validate(copy,2*n-50)==TLS13_EBADREC);
    size_t hybrid_n=server_hello(copy,1);assert(!tls13_test_server_hello_validate(copy,hybrid_n));
    memcpy(copy+hybrid_n,hello+50,n-50);server_hello_lengths(copy,hybrid_n+n-50);
    assert(tls13_test_server_hello_validate(copy,hybrid_n+n-50)==TLS13_EBADREC);
    memcpy(copy,hello,n);copy[n]=0;copy[53]++;server_hello_lengths(copy,n+1);
    assert(tls13_test_server_hello_validate(copy,n+1)==TLS13_EBADREC);
    memcpy(copy,hello,n);size_t end=n;
    for(unsigned i=0;i<62;i++){copy[end++]=0x10;copy[end++]=(unsigned char)i;copy[end++]=0;copy[end++]=0;}
    server_hello_lengths(copy,end);assert(!tls13_test_server_hello_validate(copy,end));
    copy[end++]=0x10;copy[end++]=62;copy[end++]=0;copy[end++]=0;
    server_hello_lengths(copy,end);assert(tls13_test_server_hello_validate(copy,end)==TLS13_EBADREC);
}
