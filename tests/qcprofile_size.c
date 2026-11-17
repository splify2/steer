/* SPDX-License-Identifier: GPL-3.0-only
 * Size-only comparable link probe. Do not run as a server or product. */
#include <string.h>
#include "quic.h"
#include "qccert.h"
#ifdef QC_WITH_ENDPOINT
static int connection(void *user,struct qc *q,struct qc_ops *ops,void **context) {
    (void)user;(void)q;*ops=(struct qc_ops){0};*context=NULL;return 0;
}
#endif
int main(int argc,char **argv) {
    struct qc_ops ops={0};struct qc *q=NULL;
    struct qc_cfg cfg={.host="127.0.0.1",.port=9,.sni="localhost",.alpn="qcecho",
                      .ca_pem=(const uint8_t *)qc_cert_pem,.ca_pem_n=sizeof qc_cert_pem-1};
#ifdef QC_WITH_ENDPOINT
    if(argc>1&&!strcmp(argv[1],"server")) {
        struct qc_endpoint *ep=NULL;
        struct qc_endpoint_ops endpoint_ops={.on_connection=connection};
        struct qc_endpoint_cfg server={.max_connections=2,.server={.bind_host="127.0.0.1",.alpn="qcecho",
            .cert_der=qc_cert_der,.cert_n=sizeof qc_cert_der,.key_der=qc_key_der,.key_n=sizeof qc_key_der}};
        if(qc_endpoint_open(&server,&endpoint_ops,NULL,&ep)) return 1;
        (void)qc_endpoint_on_readable(ep);(void)qc_endpoint_on_timer(ep);
        (void)qc_endpoint_timeout_ms(ep);qc_endpoint_free(ep);return 0;
    }
#else
    (void)argc;(void)argv;
#endif
    if(qc_open(&cfg,&ops,NULL,&q)) return 1;
    (void)qc_on_readable(q);(void)qc_on_timer(q);qc_free(q);return 0;
}
