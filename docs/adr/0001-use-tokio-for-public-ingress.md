# Use Tokio for the public ingress data plane

Public-hosting mode will migrate listeners, ClientHello readiness, relay I/O,
cancellation, and graceful drain to Tokio because the accepted target of
20,000 concurrent connections cannot use the existing native
thread-per-connection model safely. The current implementation will first gain
strict admission limits as a transitional safety baseline; certificate probes
and PHXP operations may remain in bounded blocking pools until their async
interfaces preserve existing trust and descriptor-ownership semantics.
