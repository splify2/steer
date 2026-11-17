/* SPDX-License-Identifier: GPL-3.0-only
 * Standalone TLS material validation probe. Prints only acceptance, never bytes. */
#include "qcssl.h"
#include "inbound_tls.h"
#include <stdio.h>
int main(int argc,char **argv) {
    struct steer_draft_tls_material material;void *context;
    if(argc!=3)return 2;
    if(steer_draft_tls_material_load(argv[1],argv[2],&material))return 2;
    context=qcssl_ctx_server(material.certificate,material.certificate_length,material.private_key,material.private_key_length);
    steer_draft_tls_material_clear(&material);
    printf("TLS material accepted=%d\n",context!=NULL);
    if(context)qcssl_ctx_free(context);
    return context?0:1;
}
