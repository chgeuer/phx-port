# Use one production ingress trust domain

The first public-hosting deployment treats ingress and all operator-owned
workloads as one security trust domain under a shared dedicated service
identity. This deliberately enables same-UID PHXP handoff as the preferred
delivery path and accepts that compromise of one workload may expose secrets
and sockets available to the shared identity. This model is not multi-tenant
isolation; onboarding an untrusted workload requires revisiting the identity
and handoff design.
