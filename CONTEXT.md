# phx-port Ingress

`phx-port` provides stable workload identities and can route public TLS
connections to independently operated workloads without taking ownership of
their TLS certificates.

## Language

**Ingress Node**:
One host-local `phx-port` ingress instance and the workloads it can reach over
that host's loopback interface.
_Avoid_: Proxy server, cluster member

**Workload**:
An application listener identified by a logical production ID and role, or by
canonical project path and role during development.
_Avoid_: Site, backend server, filesystem directory

**Route Declaration**:
Operator configuration assigning one exact public hostname to one workload.
_Avoid_: Route cache, discovered route

**Verified Route**:
A host-local activation of a route after its workload proves control of a
trusted certificate valid for the declared hostname.
_Avoid_: Configured route

**Symmetric Deployment**:
Two or more ingress nodes with equivalent route declarations and equivalent
local workload deployments.
_Avoid_: Shared-state cluster

**Ingress Trust Domain**:
The ingress and all hosted workloads that intentionally share one operating-
system security identity and compromise boundary.
_Avoid_: Tenant, isolated workload group

**Delivery Policy**:
The rule that prefers original-socket handoff for a capable workload and uses
encrypted loopback relay when handoff is unavailable before descriptor
delivery.
_Avoid_: Routing policy, fallback proxy

**Hosting Profile**:
The operating posture that selects development login-user ownership or
production dedicated-service-user ownership without changing routing
semantics.
_Avoid_: Operating system mode, environment

**Port Registry**:
The host-local, workload-writable mapping from workload identity and role to a
stable loopback port.
_Avoid_: Ingress configuration, route cache

## Relationships

- An **Ingress Node** reaches only its host-local **Workloads**
- A **Route Declaration** identifies exactly one **Workload**
- A **Verified Route** is derived independently on each **Ingress Node**
- A **Symmetric Deployment** contains equivalent **Route Declarations** and
  **Workloads** on every **Ingress Node**
- Every production **Workload** belongs to the same **Ingress Trust Domain**
- The **Delivery Policy** applies only after a **Verified Route** selects a
  **Workload**
- A **Hosting Profile** selects the local identity that owns the **Ingress Trust
  Domain**
- Every **Workload** may atomically create or read its own role assignments in
  the host-local **Port Registry**

## Example dialogue

> **Operator:** "Does active-active ingress require a shared route database?"
> **Developer:** "No. In a **Symmetric Deployment**, every **Ingress Node**
> independently turns the same **Route Declarations** into host-local
> **Verified Routes** by probing its own **Workloads**."

## Flagged ambiguities

- "Across multiple hosts" means independent active-active **Ingress Nodes**
  behind external traffic distribution, not one distributed `phx-port`
  process.
- A **Symmetric Deployment** is a later availability milestone; the first
  production pilot contains one **Ingress Node**.
- "Independent projects" means independently deployed **Workloads**, not
  mutually isolated security tenants; compromise of one may compromise the
  shared **Ingress Trust Domain**.
- Public-hosting route authority comes from exact **Route Declarations**;
  certificate verification proves a declaration before it becomes a
  **Verified Route**.
- "Production user" means the dedicated service identity selected by the
  production **Hosting Profile**; development uses the interactive login user.
- "Project identity" in production means a logical **Workload** ID, not a
  checkout or release path; canonical paths remain development identity.
- "Config" does not refer to one file: operator-owned ingress configuration,
  the workload-writable **Port Registry**, and derived verified-route state
  have different authority.
- The development **Hosting Profile** is the default and preserves the
  home-directory, working-directory-derived, zero-bootstrap workflow.
