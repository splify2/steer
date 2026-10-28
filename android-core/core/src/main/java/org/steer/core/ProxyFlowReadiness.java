package org.steer.core;

import java.io.IOException;

/** Upstream transport/request evidence, NOT a local TUN SYN-ACK or end-target
 * traffic proof. Protocols without a positive CONNECT response can only attest
 * transport establishment +initial request submission. Waiting for their first
 * payload before frontend200 can deadlock client-first TLS applications.
 * The native owner must report protocol-appropriate success/failure here.
 * No default success implementation: an unwired bridge cannot enable a proxy. */
public interface ProxyFlowReadiness {
    Pending begin(byte[] alias,int targetPort,int localPort)throws IOException;
    interface Pending extends AutoCloseable {
        boolean awaitReady(long deadlineNanos,AuthenticatedProxy.Cancellation cancellation)
            throws IOException,InterruptedException;
        /** Prompt, idempotent cancellation/unregistration, no network IO. */
        @Override void close();
    }
}
