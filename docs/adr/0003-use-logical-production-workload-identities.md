# Use logical workload identities in production

Production configuration identifies each workload with an explicit stable
logical ID and role rather than its canonical filesystem path. Route
declarations, stable port assignments, and PHXP endpoint derivation use this
identity so symmetric hosts may deploy equivalent workloads at different local
paths. Development retains canonical project paths for its zero-configuration
workflow, and production paths remain optional diagnostic metadata rather than
routing authority.
