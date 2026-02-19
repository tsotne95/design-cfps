# CFP-XXX: Shared Policy Map with BPF Arena

**SIG: SIG-Policy, SIG-Datapath, SIG-Scalability** 

**Begin Design Discussion:** 2026-02-19

**Cilium Release:** 1.20+

**Authors:** Tsotne <tsotne@google.com>

**Status:** Proposal

---

# BPF Arena Shared Policy Map Architecture

## Executive Summary

The **Arena Shared Policy Map** is a fundamental re-architecture of Cilium's datapath that solves the scaling bottleneck of per-endpoint BPF maps. By decoupling policy memory from pod count, it enables massive scale and stability improvements.

**Why this change is critical:**
*   **Massive Scalability:** Decouples policy storage from pod count, supporting 500+ pods per node and 100k+ identities by eliminating per-endpoint map duplication.
*   **Operational Efficiency:** Reduces kernel memory footprint by **90-99%** in production-scale clusters where policies are significantly shared (e.g., sidecars, common egress, CIDR expansions).
*   **Operational Stability:** Significantly mitigates the risk of map exhaustion and prevents "Lockdown Mode" outages by utilizing a larger, shared memory pool.
*   **Performance:** Accelerates identity updates by up to **100x** during high churn by updating a single shared map instead of N endpoint maps.

> [!NOTE]
> **Scoping:** While efficiency gains are massive at scale, the Arena architecture introduces a small constant baseline overhead (~16MB virtual, ~4-8KB physical paged-in pages) and central bookkeeping. In very small, idle clusters with unique per-pod policies, the legacy pure-LPM approach may have a lower initial footprint. Gains are realizeable when the cost of duplication exceeds this baseline.

## Motivation: Why This Work Was Needed

### The Core Problem

Cilium enforces network policy at the kernel level using BPF maps. In the legacy architecture, **every endpoint gets its own dedicated BPF policy map** (`cilium_policy_v2_<endpoint_id>`). Each map must allocate memory for every key-value pair, even if the rules are structurally identical across endpoints.

This design worked well when clusters were small. As Kubernetes deployments grew to hundreds or thousands of pods per node, this per-endpoint duplication became a critical bottleneck—consuming excessive kernel memory, hitting hard BPF map limits, and causing silent packet drops in production.

---

### Scenario 1: The "World Identity Explosion"

**The single most common trigger for this work.**

A platform team applies a simple egress policy to allow pods to reach external services:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-external-egress
spec:
  endpointSelector:
    matchLabels:
      app: api-gateway
  egress:
    - toCIDR: ["0.0.0.0/0"]
```

This looks like one rule. In reality, Cilium must expand `0.0.0.0/0` to cover **every known CIDR identity** in the cluster—because any external IP also falls within `0.0.0.0/0`. While it does not allow traffic to in-cluster pod identities (which are managed by `toEndpoints`), a typical production cluster can still have thousands of unique CIDR identities due to external service traffic, IP caches, and broad FQDN policies.

**What actually happens:**

```
┌─────────────────────────────────────────────────────────────────────────┐
│           THE "WORLD" EXPLOSION                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  User writes: toCIDR: ["0.0.0.0/0"]                                     │
│                                                                         │
│  Cilium expands to:                                                     │
│    Identity 2  (World)              → Allow egress                      │
│    Identity 9  (World-IPv4)         → Allow egress                      │
│    Identity 10 (World-IPv6)         → Allow egress                      │
│    Identity 16777217 (cidr:1.1.1.1) → Allow egress                      │
│    Identity 16777218 (cidr:8.8.8.8) → Allow egress                      │
│    Identity 16777219 (cidr: ...)    → Allow egress                      │
│    ... every CIDR identity ...                                          │
│    Identity 16782549 (cidr: ...)    → Allow egress                      │
│    ─────────────────────────────────                                    │
│                                                                         │
│  Now multiply by pods ON A SINGLE NODE:                                 │
│    20 api-gateway pods × 1,000 entries = 20,000 policy map entries      │
│   100 api-gateway pods × 1,000 entries = 100,000 policy map entries     │
│   (This is where the per-node BPF map limit bottle-neck occurs)         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Real impact:** A customer running 20 pods on a single node with `0.0.0.0/0` egress and ~1,000 CIDR identities in their cluster consumes **20,000+ policy map entries** on that node—where only **~1,020 unique entries** actually exist. That's **~95% wasted memory** on every node carrying these pods.

---

### Scenario 2: Service Mesh Sidecars & Common Policies

A security team deploys a `CiliumNetworkPolicy` for a ubiquitous sidecar (e.g., Istio proxy, logging agent) injected into EVERY pod:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: sidecar-policy-allow-monitoring
spec:
  endpointSelector:
    matchLabels:
      app: sidecar-proxy
  ingress:
    - fromEntities: ["prometheus"]
      toPorts:
        - ports: [{ port: "15020", protocol: TCP }]
  egress:
    - toEntities: ["kube-dns"]
    - toCIDR: ["0.0.0.0/0"]
```

**The problem:** This sidecar runs in **every pod**. Since policy is applied per-pod (Endpoint), the sidecar's required policy rules are duplicated into **every single Pod's policy map**.

```
┌─────────────────────────────────────────────────────────────────────────┐
│           SIDECAR / COMMON POLICY DUPLICATION                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Node with 100 pods (each has a sidecar):                               │
│    - Legacy: Each Pod Endpoint gets its OWN independent policy map      │
│    - 100 endpoints × 50 rules (sidecar policy) = 5,000 entries          │
│    - Memory: 5,000 × 64 bytes = 320 KB + 100 × 16KB map overhead        │
│    - Total: ~2 MB kernel memory just for sidecars on this node          │
│                                                                         │
│  With Shared Policy Map (Arena):                                        │
│    - "sidecar-policy-allow-monitoring" is stored ONCE in the Arena      │
│    - 100 endpoints point to the SAME RuleSetID in the Overlay Map       │
│    - Memory: 50 rules × 64 bytes = 3.2 KB                               │
│    - Overlay: 100 × ~300 bytes = 30 KB                                  │
│    - Total: ~33 KB (vs 2 MB = 98% reduction)                            │
│                                                                         │
│  NOTE: For a DaemonSet (1 pod per node), the benefit comes from         │
│  eliminated map overhead (no 16KB per-map cost), not rule deduplication │
│  (since there is only 1 instance per node).                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### Scenario 3: Policy Map Exhaustion and Silent Drops

The BPF policy map has a hard size limit: **16,384 entries** by default (`--bpf-policy-map-max`). When this limit is exceeded, Cilium cannot insert new policy rules.

**What happens in production:**

```
┌─────────────────────────────────────────────────────────────────────────┐
│           MAP EXHAUSTION CASCADE                                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Timeline of a real incident:                                           │
│                                                                         │
│  T+0:  Cluster has 200 identities, pods have ~200 policy entries each   │
│         Map usage: 200/16384 = 1.2%  ← Looks fine                       │
│                                                                         │
│  T+1h: New microservices deployed, identity count grows to 500          │
│         0.0.0.0/0 policies expand: 500 entries per endpoint             │
│         Map usage: 500/16384 = 3%  ← Still fine                         │
│                                                                         │
│  T+1d: CIDR policies added for external APIs (S3, RDS, etc.)            │
│         Each CIDR range gets its own identity                           │
│         Identity count: 2,000                                           │
│         Map usage: 2,000/16384 = 12%  ← Growing                         │
│                                                                         │
│  T+1w: Identity count reaches 10,000 (large multi-tenant cluster)       │
│         Pods with 0.0.0.0/0 now have 10,000 entries each                │
│         Map usage: 10,000/16384 = 61%  ← Warning territory              │
│                                                                         │
│  T+2w: New CiliumNetworkPolicy adds per-port rules                      │
│         Each identity × port = new entry                                │
│         Map fills up: 16,384/16,384 = 100%                              │
│                                                                         │
│  RESULT:                                                                │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │ level=error msg="policy map max entries limit exceeded"        │     │
│  │ endpoint=701 entries=16384 adds=52 maxEntries=16384            │     │
│  │                                                                │     │
│  │ NEW POLICY RULES CANNOT BE INSERTED.                           │     │
│  │ Endpoint enters LOCKDOWN mode.                                 │     │
│  │ Traffic may be DROPPED or ALLOWED incorrectly.                 │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                         │
│  Code path (pkg/endpoint/bpf.go:1297-1322):                             │
│  func (e *Endpoint) startLockdownLocked(changeSize int) error {         │
│      e.getLogger().Warn(                                                │
│          "The policy map exceeds the max entries limit, locking down")  │
│      e.endpointPolicyLockdown()                                         │
│      e.lockdown = true                                                  │
│      return ErrPolicyEntryMaxExceeded                                   │
│  }                                                                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**The lockdown mechanism** (`pkg/endpoint/bpf.go:1288-1322`):
- When `desiredPolicy.Len() + changeSize > policyMap.MaxEntries()`, the endpoint enters lockdown
- New rules are rejected with `ErrPolicyEntryMaxExceeded`
- The endpoint may drop legitimate traffic it should allow

**Transient drops during reordering** (`pkg/endpoint/bpf.go`):
- In high-scale environments where the map is near capacity, Cilium is forced to delete old entries before adding new ones to prevent overflow.
- During this brief window, traffic matching the deleted entries is dropped.
- This causes intermittent, hard-to-debug connectivity issues for workloads operating near the map limit.

**Arena Advantage:** The Arena architecture avoids this by allocating the new RuleSet *before* updating the endpoint's reference.
- **Atomic Swap:** The Endpoint Overlay entry is updated only after the new RuleSet is successfully written to the Arena.
- **Safe Failure:** If the Arena is full, the allocation fails, and the endpoint retains its existing (valid) policy, preventing transient drops.

---

### Scenario 4: High Pod Density Nodes

Modern Kubernetes clusters increasingly pack many pods per node:

```
┌─────────────────────────────────────────────────────────────────────────┐
│           HIGH POD DENSITY                                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Node with 200 pods (common in serverless/FaaS workloads):              │
│                                                                         │
│  Legacy per-endpoint maps:                                              │
│    200 endpoints × 16KB map overhead each = 3.2 MB (map metadata)       │
│    200 endpoints × 50 rules × 64 bytes    = 640 KB (rule data)          │
│    Total kernel memory locked: ~3.8 MB                                  │
│                                                                         │
│  But with CIDR expansion (500 identities):                              │
│    200 endpoints × 500 rules × 64 bytes = 6.4 MB (rule data alone)      │
│    Total: ~9.6 MB locked kernel memory for policy maps                  │
│                                                                         │
│  At 1,000 identities:                                                   │
│    200 endpoints × 1,000 rules × 64 bytes = 12.8 MB                     │
│    Total: ~16 MB locked kernel memory                                   │
│                                                                         │
│  This is LOCKED kernel memory (RLIMIT_MEMLOCK):                         │
│    - Cannot be swapped                                                  │
│    - Reduces available memory for page cache                            │
│    - Competes with other BPF maps (connection tracking, NAT, etc.)      │
│    - On memory-constrained nodes, can trigger OOM kills                 │
│                                                                         │
│  With Shared Policy Map (assuming 10 unique policies):                  │
│    Arena: 10 unique rule sets × 500 × 64 bytes = 320 KB                 │
│    Overlay: 200 entries × 388 bytes = 78 KB                             │
│    Total: ~400 KB  (vs 16 MB = 97.5% reduction)                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### Scenario 5: Identity Churn and Policy Map Thrashing

In dynamic clusters, identities are constantly created and destroyed as pods come and go:

```
┌─────────────────────────────────────────────────────────────────────────┐
│           IDENTITY CHURN                                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  A CI/CD pipeline creates short-lived pods constantly:                  │
│    - 50 new pods/minute (build jobs, test runners)                      │
│    - Each gets a unique identity (different label combinations)         │
│    - Identity count fluctuates: 500 → 800 → 600 → 900 → ...             │
│                                                                         │
│  For endpoints with 0.0.0.0/0 policy:                                   │
│    - Every new identity triggers a policy map update                    │
│    - Legacy: Update EVERY endpoint's individual map                     │
│    - 100 pods × 1 map write per identity change = 100 BPF operations    │
│    - At 50 identity changes/minute = 5,000 map writes/minute            │
│                                                                         │
│  With Shared Policy Map:                                                │
│    - New identity triggers ONE shared LPM trie update                   │
│    - 100 pods: 1 BPF write (shared rule set updated once)               │
│    - At 50 identity changes/minute = 50 map writes/minute               │
│    - 100x reduction in BPF syscall overhead                             │
│                                                                         │
│  Agent CPU impact:                                                      │
│    Legacy:  5,000 syscalls/min × ~1µs each = 5ms/min                    │
│    Arena:      50 syscalls/min × ~1µs each = 0.05ms/min                 │
│                                                                         │
│  Nuance:                                                                │
│    - Legacy maps are actually efficient for *pod deletion* (just drop   │
│      the whole map).                                                    │
│    - The pain comes from the *remaining* pods needing updates for every │
│      new/churning identity (the "lock step" update problem).            │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### Scenario 6: Multi-Tenant Clusters with Namespace Isolation

Enterprise clusters often have hundreds of namespaces with network policies:

```
┌─────────────────────────────────────────────────────────────────────────┐
│           MULTI-TENANT NAMESPACE ISOLATION                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  100 namespaces, each with:                                             │
│    - Default deny-all ingress policy                                    │
│    - Allow ingress from same namespace                                  │
│    - Allow egress to DNS (port 53)                                      │
│    - Allow egress to 0.0.0.0/0 on port 443 (HTTPS)                      │
│                                                                         │
│  Each namespace has ~20 pods.                                           │
│  Total: 2,000 endpoints.                                                │
│                                                                         │
│  The policies look different (different namespace selectors) but        │
│  structurally they are THE SAME PATTERN with different identities.      │
│                                                                         │
│  BEST PRACTICE: ClusterwidePolicies (CCNP) for common infrastructure    │
│  (DNS, logging, monitoring) significantly increase deduplication        │
│  efficiency compared to namespace-scoped duplicates.                    │
│                                                                         │
│  Legacy:                                                                │
│    2,000 endpoints × ~100 rules each = 200,000 policy entries           │
│    Memory: ~12.8 MB locked kernel memory                                │
│                                                                         │
│  Arena (with deduplication):                                            │
│    ~100 unique rule set patterns × 100 rules = 10,000 entries           │
│    Overlay: 2,000 × 388 bytes = 776 KB                                  │
│    Memory: ~1.4 MB  (89% reduction)                                     │
│                                                                         │
│  Magnification:                                                         │
│    - Clusterwide Network Policies (CCNPs) or "Base Policies" exacerbate │
│      Scenarios 1-5 because they remove namespace boundaries.            │
│    - A single CCNP rule applies to ALL endpoints in the cluster,        │
│      effectively forcing the "Global Scale" problem onto every node.    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

### Summary: Why Arena Shared Policy Maps

| Problem | Real Impact | Arena Solution |
|---------|-------------|----------------|
| **World 0.0.0.0/0 expansion** | 250+ entries duplicated per pod | Store once, reference N times |
| **Policy map exhaustion** | `ErrPolicyEntryMaxExceeded`, packet drops | Shared trie with 131K capacity/refcounting |
| **Lockdown mode** | Endpoint blocks all new policies | Shared map mitigates per-endpoint fill-up |
| **Transient drops** | Delete-before-add during map pressure | No per-endpoint map pressure |
| **High pod density** | 16+ MB locked kernel memory | ~400 KB for same workload |
| **Identity churn** | N map writes per identity change | 1 map write per shared entry |
| **Multi-tenant isolation** | Structurally identical policies duplicated | Deduplication across namespaces |
| **Garbage Collection** | Trivial (Map drop on delete) | Complex (Refcounting + Agent-restart reclamation in POC) |

---

## Overview

The Arena Shared Policy Map architecture addresses all of the above scenarios by replacing per-endpoint policy maps with a shared, deduplicated system. Instead of N copies of the same rules, the arena stores rules **once** and lets endpoints **reference** them through a lightweight overlay map.

### Legacy Architecture (Per-Endpoint Maps)

In the traditional Cilium design, each endpoint has its own dedicated policy map:

```
┌─────────────────────────────────────────────────────────────┐
│                    LEGACY ARCHITECTURE                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Endpoint 701                    Endpoint 702               │
│  ┌──────────────────┐           ┌──────────────────┐        │
│  │ cilium_policy_701│           │ cilium_policy_702│        │
│  ├──────────────────┤           ├──────────────────┤        │
│  │ Rule: Allow 80   │           │ Rule: Allow 80   │ ◄──┐   │
│  │ Rule: Allow 443  │           │ Rule: Allow 443  │    │   │
│  │ Rule: Allow 53   │           │ Rule: Allow 53   │    │   │
│  │ Rule: Deny *     │           │ Rule: Deny *     │    │   │
│  └──────────────────┘           └──────────────────┘    │   │
│                                                         │   │
│  Endpoint 703                    Endpoint 704           │   │
│  ┌──────────────────┐           ┌──────────────────┐    │   │
│  │ cilium_policy_703│           │ cilium_policy_704│    │   │
│  ├──────────────────┤           ├──────────────────┤    │   │
│  │ Rule: Allow 80   │ ◄─────────│ Rule: Allow 80   │────┘   │
│  │ Rule: Allow 443  │  SAME     │ Rule: Allow 443  │        │
│  │ Rule: Allow 53   │  RULES    │ Rule: Allow 53   │        │
│  │ Rule: Deny *     │  COPIED   │ Rule: Deny *     │        │
│  └──────────────────┘           └──────────────────┘        │
│                                                             │
│  Memory: 4 endpoints × 16KB each = 64KB (for just 4 rules!) │
└─────────────────────────────────────────────────────────────┘
```

**Problems:**
- Same rules duplicated across endpoints with identical policies
- Memory usage scales as: `O(endpoints × rules_per_endpoint)`
- At scale: 10,000 endpoints × 16KB = **160MB** just for policy maps

---

## Arena Architecture Solution

### High-Level Design

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      ARENA SHARED ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    OVERLAY MAP (cilium_policy_o)                │    │
│  │                    Key: Endpoint ID → Overlay Entry             │    │
│  ├─────────────────────────────────────────────────────────────────┤    │
│  │  EP 701 → [SharedRefs: {handle_A}, PrivateOverrides: {}]        │    │
│  │  EP 702 → [SharedRefs: {handle_A}, PrivateOverrides: {}]        │    │
│  │  EP 703 → [SharedRefs: {handle_A, handle_B}, PrivateOverrides: {}]   │
│  │  EP 704 → [SharedRefs: {handle_A}, PrivateOverrides: {port:8080}]    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                 SHARED LPM TRIE (cilium_policy_s)               │    │
│  │                 Key: rule_set_id + LPM prefix → Arena Offset    │    │
│  ├─────────────────────────────────────────────────────────────────┤    │
│  │  {rule_set_id=A, prefix=80/TCP}  → arena_offset: 0x1000         │    │
│  │  {rule_set_id=A, prefix=443/TCP} → arena_offset: 0x1040         │    │
│  │  {rule_set_id=A, prefix=53/UDP}  → arena_offset: 0x1080         │    │
│  │  {rule_set_id=B, prefix=8443/TCP}→ arena_offset: 0x10C0         │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    BPF ARENA (cilium_policy_a)                  │    │
│  │                    Shared Memory for Full Rule Data             │    │
│  ├─────────────────────────────────────────────────────────────────┤    │
│  │  0x1000: [PolicyEntry: Allow, Port:80, Proto:TCP, ...]          │    │
│  │  0x1040: [PolicyEntry: Allow, Port:443, Proto:TCP, ...]         │    │
│  │  0x1080: [PolicyEntry: Allow, Port:53, Proto:UDP, ...]          │    │
│  │  0x10C0: [PolicyEntry: Allow, Port:8443, Proto:TCP, ...]        │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  Memory: 1 overlay + 1 shared trie + 1 arena ≈ 20KB (for same 4 rules)  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Overlay Map (`cilium_policy_o`)

**Purpose:** Maps each endpoint to its policy references.

```c
// BPF Definition (bpf/lib/policy.h)
struct overlay_entry {
    __u8 shared_ref_count;                              // Number of shared rule sets
    __u8 private_count;                                 // Number of private overrides
    __u8 pad[2];                                        // Alignment padding
    __u32 shared_handles[MAX_SHARED_REFS];              // References to shared rule sets
    struct overlay_private_entry private_overrides[MAX_PRIVATE_OVERRIDES];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                                 // Endpoint ID
    __type(value, struct overlay_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, POLICY_MAP_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_policy_o __section_maps_btf;
```

**Go Definition (pkg/maps/policymap/sharedmap.go):**
```go
type OverlayEntryBPF struct {
    SharedRefCount   uint8
    PrivateCount     uint8
    Pad              [2]uint8
    SharedRefs       [DefaultMaxSharedRefs]uint32
    PrivateOverrides [DefaultMaxPrivateOverride]OverlayPrivateEntry
}
```

**Key insight:** The overlay map is indexed by **Endpoint ID** (not security identity).

### 2. Shared LPM Trie (`cilium_policy_s`)

**Purpose:** Stores policy rules with LPM (Longest Prefix Match) for port ranges.

```c
struct shared_lpm_key {
    struct bpf_lpm_trie_key lpm_key;  // Prefix length for port matching
    __u32 rule_set_id;                // Identifies the rule set (for sharing)
    __u32 sec_label;                  // Remote identity (0 for L4-only)
    __u8  egress:1,                   // Direction (0=ingress, 1=egress)
          pad:7;
    __u8  protocol;                   // L4 protocol (can be LPM wildcarded)
    __be16 dport;                     // Destination port (can be LPM wildcarded)
} __attribute__((packed));

struct shared_lpm_value {
    __u32 arena_offset;               // Offset in arena to policy_entry data
    __u8  flags;                      // deny:1, reserved:2, lpm_prefix_length:5
    __u8  auth_type;                  // auth_type:7, has_explicit_auth_type:1
    __be16 proxy_port;                // Proxy redirect port (network byte order)
} __attribute__((packed));
```

**LPM Prefix Matching:**
```
Prefix bits breakdown (96 bits total):
┌────────────────────────────────────────────────────┐
│ Bits 0-71:   RuleSetID + Identity + Egress (Exact) │
│ Bits 72-79:  Protocol (8 bits)                     │
│ Bits 80-95:  Port (16 bits)                        │
└────────────────────────────────────────────────────┘

Examples:
- prefix=72: Match specific RuleSet+ID, ANY protocol, ANY port
- prefix=80: Match specific RuleSet+ID + protocol, ANY port
- prefix=96: Match specific RuleSet+ID + protocol + port
```

### 3. BPF Arena (`cilium_policy_a`)

**Purpose:** Shared memory region for full policy entry data.

```c
// Arena memory layout
```c
// Arena memory layout
struct arena_policy_entry {
    __be16 proxy_port;     // Proxy redirect port (network byte order)
    __u8   flags;          // deny:1, reserved:2, lpm_prefix_length:5
    __u8   auth_type;      // auth_type:7, has_explicit_auth_type:1
    __u32  precedence;
    __u32  cookie;
} __attribute__((packed));
```


**Arena benefits:**
- Shared between BPF and userspace (zero-copy updates)
- Memory allocated once, referenced by multiple endpoints
- Supports dynamic growth up to configured maximum

---

## Packet Processing Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        PACKET PROCESSING FLOW                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. Packet arrives at endpoint                                          │
│     ┌──────────────────────────────────────────────────┐                │
│     │ Packet: src=10.0.0.5, dst=10.0.0.10:80, TCP      │                │
│     │ Endpoint ID: 701, Security Identity: 40500       │                │
│     └──────────────────────────────────────────────────┘                │
│                              │                                          │
│                              ▼                                          │
│  2. Lookup overlay by ENDPOINT ID (not security identity!)              │
│     ┌──────────────────────────────────────────────────┐                │
│     │ ep_id = EFFECTIVE_EP_ID;  // = 701               │                │
│     │ overlay = map_lookup(&cilium_policy_o, &ep_id);  │                │
│     └──────────────────────────────────────────────────┘                │
│                              │                                          │
│     Result: overlay = {                                                 │
│       shared_ref_count: 1,                                              │
│       shared_handles: [handle_A],                                       │
│       private_count: 0                                                  │
│     }                                                                   │
│                              │                                          │
│                              ▼                                          │
│  3. Check private overrides first (highest precedence)                  │
│     ┌──────────────────────────────────────────────────┐                │
│     │ for each private_override:                       │                │
│     │   if matches(packet, override): return override  │                │
│     └──────────────────────────────────────────────────┘                │
│                              │                                          │
│                              ▼                                          │
│  4. Search shared rule sets via LPM trie (L3 & L4)                      │
│     ┌──────────────────────────────────────────────────┐                │
│     │ for each handle in overlay.shared_handles:       │                │
│     │   // Lookup 1: L3 Specific (identity=40500)      │                │
│     │   // Lookup 2: L4 Only (identity=0)              │                │
│     │   key = {rule_set_id=handle, identity=..., ...}  │                │
│     │   val = lpm_lookup(&cilium_policy_s, &key);      │                │
│     │                                                  │                │
│     │   if val:                                        │                │
│     │     entry = bpf_probe_read_user(arena + offset); │                │
│     │     if entry.precedence > best.precedence:       │                │
│     │        best = entry;                             │                │
│     └──────────────────────────────────────────────────┘                │
│                              │                                          │
│                              ▼                                          │
│  5. Apply policy decision                                               │
│     ┌──────────────────────────────────────────────────┐                │
│     │ if best and best.action == ALLOW: forward packet │                │
│     │ if best and best.action == DENY: drop packet     │                │
│     │ (Default deny if no match found)                 │                │
│     └──────────────────────────────────────────────────┘                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Memory Deduplication

### Per-Rule Deduplication with Reference Counting

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    PER-RULE DEDUPLICATION EXAMPLE                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Scenario: 3 Endpoints with overlapping policies                        │
│                                                                         │
│  EP 701: Allow 80, Allow 443, Allow 53                                  │
│  EP 702: Allow 80, Allow 443, Allow 8080                                │
│  EP 703: Allow 80, Allow 443                                            │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────┐      │
│  │                      RULE POOL (Arena)                        │      │
│  ├───────────────────────────────────────────────────────────────┤      │
│  │  Rule Hash    │ Arena Offset │ Refcount │ Content             │      │
│  │───────────────┼──────────────┼──────────┼─────────────────────│      │
│  │  0xABCD1234   │ 0x1000       │ 3        │ Allow TCP/80        │      │
│  │  0xBCDE2345   │ 0x1040       │ 3        │ Allow TCP/443       │      │
│  │  0xCDEF3456   │ 0x1080       │ 1        │ Allow UDP/53        │      │
│  │  0xDEF04567   │ 0x10C0       │ 1        │ Allow TCP/8080      │      │
│  └───────────────────────────────────────────────────────────────┘      │
│                                                                         │
│  Memory saved: Instead of 8 rule copies (3+3+2), only 4 unique rules    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```
> [!NOTE]
> **Key vs. Value Deduplication Nuance**
> While the **Arena values** (verdict data) are globally deduplicated via the `rulePool`, the **LPM keys** (Identity, Proto, Port) still exist as separate entries in the shared trie (`cilium_policy_s`) for each unique rule set. However, since most rule sets are themselves shared (e.g., all pods in a Deployment share one `rule_set_id`), the total number of trie entries remains significantly lower than the legacy per-endpoint model.

### Go Implementation (pkg/maps/policymap/arena_allocator.go)

```go
type rulePoolEntry struct {
    arenaOffset uint32  // Location in arena memory
    refcount    int     // Number of endpoints using this rule
}

type ArenaAllocator struct {
    rulePool      map[uint64]rulePoolEntry  // hash → pool entry
    nextArenaOff  uint32                     // Next free offset
}

// WriteRulesToSharedLPM writes rules to the shared LPM trie and arena.
// It implements GLOBAL PER-RULE DEDUPLICATION.
func (a *ArenaAllocator) WriteRulesToSharedLPM(rules []SharedLPMRule) error {
    // Phase 1: Process arena allocation and collect keys/values
    keys := make([]SharedLPMKey, len(rules))
    values := make([]SharedLPMValue, len(rules))

    for i, rule := range rules {
        // Compute hash of rule DATA (verdict fields only, like ProxyPort, Deny, Precedence)
        hash := computeRuleHash(rule)

        var arenaOffset uint32
        if entry, exists := a.rulePool[hash]; exists {
            // GLOBAL DEDUPLICATION: Reuse existing rule
            arenaOffset = entry.arenaOffset
            // Increment refcount
            a.rulePool[hash] = rulePoolEntry{entry.arenaOffset, entry.refcount + 1}
        } else {
            // New unique rule - allocate in arena (if space available)
            arenaOffset = a.nextArenaOff
            a.nextArenaOff += ArenaPolicyEntrySize
            
            // Write rule to arena variable "arena_data"
            writeToArena(arenaOffset, rule)

            // Add to pool
            a.rulePool[hash] = rulePoolEntry{arenaOffset, 1}
        }

        // Build LPM key (RuleSetID + Identity + Proto + Port)
        keys[i] = buildSharedLPMKey(rule)
        
        // Build LPM value pointing to shared arena data
        values[i] = SharedLPMValue{
            ArenaOffset: arenaOffset,
            Flags:       buildFlags(rule), // e.g. deny bit, prefix len
            // ...
        }
    }

    // Phase 2: Batch update LPM trie
    return a.lpmMap.BatchUpdate(keys, values, ...)
}
```

---

## Memory Savings Analysis

### Calculation Formula

```
Legacy Memory = num_endpoints × rules_per_endpoint × entry_size
Arena Memory  = num_unique_rules × entry_size + overlay_overhead

Savings = Legacy Memory - Arena Memory
Savings % = (Savings / Legacy Memory) × 100
```

### Real-World Example

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    MEMORY SAVINGS EXAMPLE                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Scenario: Kubernetes cluster with microservices                        │
│                                                                         │
│  - 1,000 endpoints (pods)                                               │
│  - Average 50 policy rules per endpoint                                 │
│  - 80% rule overlap (common rules like DNS, metrics, health checks)     │
│  - Arena Policy Entry size: 12 bytes (packed)                           │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                     LEGACY ARCHITECTURE                         │    │
│  │                                                                 │    │
│  │  Per-endpoint map overhead: ~4KB (BPF map metadata)             │    │
│  │  Rules storage: 1,000 × 50 × 64 bytes = 3.2 MB (est. overhead)  │    │
│  │  Map overhead: 1,000 × 4KB = 4 MB                               │    │
│  │  ─────────────────────────────────────────────                  │    │
│  │  TOTAL: ~7.2 MB                                                 │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                     ARENA ARCHITECTURE                          │    │
│  │                                                                 │    │
│  │  Unique rules: 50 × 20% unique + 50 × 80% shared/1000           │    │
│  │              = 10 + 0.04 = ~10.04 rules per endpoint effective  │    │
│  │  Total unique rules: ~10,040 (with deduplication)               │    │
│  │                                                                 │    │
│  │  Arena storage: 10,040 × 12 bytes = ~120 KB                     │    │
│  │  Overlay map: 1,000 × 300 bytes = 300 KB                        │    │
│  │  Shared LPM trie: 10,040 × 32 bytes = ~320 KB (est. overhead)   │    │
│  │  ─────────────────────────────────────────────────              │    │
│  │  TOTAL: ~740 KB                                                 │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                       SAVINGS                                   │    │
│  │                                                                 │    │
│  │  Memory Saved: 7.2 MB - 0.74 MB = ~6.46 MB                      │    │
│  │  Savings Percentage: ~90%                                       │    │
│  │                                                                 │    │
│  │  At 10,000 endpoints: ~64 MB saved                              │    │
│  │  At 100,000 endpoints: ~640 MB saved                            │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Savings by Overlap Percentage

| Endpoints | Rules/EP | Overlap % | Legacy | Arena | Savings |
|-----------|----------|-----------|--------|-------|---------|
| 100       | 50       | 50%       | 720KB  | 80KB  | 88%     |
| 100       | 50       | 80%       | 720KB  | 40KB  | 94%     |
| 1,000     | 50       | 80%       | 7.2MB  | 740KB | 90%     |
| 10,000    | 100      | 90%       | 144MB  | 8MB   | 94%     |

---

## Configuration Parameters

### Agent Configuration Options

```yaml
# cilium-config ConfigMap
data:
  # Enable arena-based shared policy maps
  enable-policy-shared-map-arena: "true"

  # Maximum shared rule set references per endpoint
  policy-shared-map-max-shared-refs: "16"

  # Maximum private override entries per endpoint
  policy-shared-map-max-private-overrides: "8"

  # Maximum entries in the shared policy LPM trie
  policy-shared-map-max-entries: "131072"
```


### Overlay Entry Size Calculation

```
overlay_entry size = 1 (shared_ref_count)
                   + 1 (private_count)
                   + 2 (padding)
                   + 4 × MAX_SHARED_REFS (shared_handles)
                   + sizeof(private_entry) × MAX_PRIVATE_OVERRIDES

With defaults (MAX_SHARED_REFS=16, MAX_PRIVATE_OVERRIDES=8):
  = 1 + 1 + 2 + (4 × 16) + (24 × 8)
  = 4 + 64 + 192
  = 260 bytes per endpoint
```

---

## Current Implementation vs Reserved Capacity

**IMPORTANT:** The current implementation uses only a subset of the reserved capacity.

```
┌─────────────────────────────────────────────────────────────────────────┐
│              ACTUAL USAGE vs RESERVED CAPACITY                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Constant               │ Reserved │ Currently Used │ Purpose           │
│  ───────────────────────┼──────────┼────────────────┼────────────────── │
│  MAX_SHARED_REFS        │ 16       │ 1              │ Rule set refs     │
│  MAX_PRIVATE_OVERRIDES  │ 8        │ 0              │ Spillover rules   │
│                                                                         │
│  WHY ONLY 1 SHARED REF IS USED:                                         │
│  ─────────────────────────────────                                      │
│  The agent pre-combines ALL policies matching an endpoint into a        │
│  single rule set before calling SyncEndpointOverlay().                  │
│                                                                         │
│  Example:                                                               │
│    - CiliumNetworkPolicy "web-access" → rules [80, 443]                 │
│    - CiliumNetworkPolicy "monitoring" → rules [9090]                    │
│    - Cluster-wide "dns" → rules [53]                                    │
│                                                                         │
│  Agent COMBINES: [80, 443, 9090, 53] → ONE rule_set_id                  │
│                                                                         │
│  Overlay entry:                                                         │
│    shared_ref_count: 1         ◄── Only 1 used                          │
│    shared_handles[0]: rule_set_id                                       │
│    shared_handles[1..15]: 0    ◄── Reserved for future                  │
│    private_count: 0            ◄── Not used (isPrivate always false)    │
│    private_overrides[]: empty  ◄── Reserved for future                  │
│                                                                         │
│  DEDUPLICATION HAPPENS ACROSS ENDPOINTS:                                │
│  ──────────────────────────────────────────                             │
│  EP 701: combined rules [80, 443, 53] → hash=ABC → rule_set_id=1        │
│  EP 702: combined rules [80, 443, 53] → hash=ABC → rule_set_id=1 REUSED!│
│  EP 703: combined rules [80, 8080]    → hash=XYZ → rule_set_id=2        │
│                                                                         │
│  refcount[1] = 2 (shared by EP 701 and 702)                             │
│  refcount[2] = 1 (only EP 703)                                          │
│                                                                         │
│  FUTURE POTENTIAL USES:                                                 │
│  ─────────────────────────                                              │
│  - MAX_SHARED_REFS > 1: Split policies by source (CNP vs CCNP)          │
│  - MAX_PRIVATE_OVERRIDES > 0: Per-endpoint proxy rules, spillover       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Policy Update Flow

When policies are added, removed, or updated:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    POLICY LIFECYCLE                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. ADD POLICY                                                          │
│  ──────────────                                                         │
│  kubectl apply -f policy-A.yaml (allows port 80)                        │
│                                                                         │
│  Agent: Computes desired state for affected endpoints                   │
│  EP 701: rules=[80] → hash=H1 → rule_set_id=1 (new)                     │
│  Overlay: shared_handles=[1]                                            │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  2. ADD ANOTHER POLICY (same endpoint)                                  │
│  ─────────────────────────────────────                                  │
│  kubectl apply -f policy-B.yaml (allows port 443)                       │
│                                                                         │
│  Agent: Re-computes desired state (COMBINED)                            │
│  EP 701: rules=[80,443] → hash=H2 → rule_set_id=2 (new)                 │
│  Old rule_set_id=1: refcount-- → if 0, DELETE from LPM trie             │
│  Overlay: shared_handles=[2]  ◄── REPLACED, not appended                │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  3. REMOVE POLICY                                                       │
│  ───────────────                                                        │
│  kubectl delete -f policy-B.yaml                                        │
│                                                                         │
│  Agent: Re-computes desired state                                       │
│  EP 701: rules=[80] → hash=H1 → rule_set_id=1 (may reuse if exists)     │
│  Old rule_set_id=2: refcount-- → DELETE from LPM trie                   │
│  Overlay: shared_handles=[1]                                            │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  4. UPDATE POLICY (modify port)                                         │
│  ────────────────────────────────                                       │
│  Edit policy-A.yaml: port 80 → port 8080                                │
│                                                                         │
│  Agent: Re-computes desired state                                       │
│  EP 701: rules=[8080] → hash=H3 → rule_set_id=3 (new)                   │
│  Old rule_set_id=1: refcount-- → DELETE from LPM trie                   │
│  Overlay: shared_handles=[3]                                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Boundaries and Limits

### Hard Limits

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SYSTEM BOUNDARIES                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. BPF Map Name Length: 15 characters maximum                          │
│     - cilium_policy_o (overlay)     ✓ 15 chars                          │
│     - cilium_policy_s (shared)      ✓ 15 chars                          │
│     - cilium_policy_a (arena)       ✓ 15 chars                          │
│                                                                         │
│  2. BPF Instruction Limit: ~1 million instructions                      │
│     - LPM trie lookup: O(1) - kernel handles internally                 │
│     - Shared refs loop: O(MAX_SHARED_REFS)                              │
│     - Private overrides: O(MAX_PRIVATE_OVERRIDES)                       │
│                                                                         │
│  3. Arena Size: Limited by system memory and BPF arena limits           │
│     - Typical max: 1GB (configurable)                                   │
│     - Each rule: ~64 bytes                                              │
│     - Max rules: ~16 million                                            │
│                                                                         │
│  4. Endpoint ID: uint16 (0-65535)                                       │
│     - Maps directly to overlay map key                                  │
│                                                                         │
│  5. Rule Set ID: uint32 (0-4 billion)                                   │
│     - Hash-based, collision handled by full comparison                  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Spillover Behavior

When an endpoint exceeds the shared reference limit:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SPILLOVER HANDLING                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Scenario: Endpoint needs 20 rule sets, but MAX_SHARED_REFS = 16        │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    Overlay Entry for EP 701                     │    │
│  │                                                                 │    │
│  │  shared_ref_count: 16 (maxed out)                               │    │
│  │  shared_handles: [A, B, C, ..., P]                              │    │
│  │                                                                 │    │
│  │  private_count: 4 (spillover rules)                             │    │
│  │  private_overrides: [rule_Q, rule_R, rule_S, rule_T]            │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  Lookup Order:                                                          │
│  1. Check private_overrides first (highest precedence)                  │
│  2. Then check shared_handles via LPM trie                              │
│                                                                         │
│  If private_overrides ALSO overflow → fall back to legacy map           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Garbage Collection & Reclamation

The shift from per-endpoint maps to a shared arena introduces significant complexity into the lifecycle of policy data.

#### Deletion Complexity
In the legacy model, deleting an endpoint's policy was as simple as dropping its BPF map. In the Arena architecture:
1.  **Overlay Removal:** The endpoint's entry in `cilium_policy_o` is deleted.
2.  **Refcount Decrement:** The `rule_set_id` refcount is decremented.
3.  **Trie Cleanup:** If the refcount drops to zero, all LPM entries for that `rule_set_id` are swept from `cilium_policy_s`.
4.  **Arena Pool Update:** For each rule removed from the trie, its corresponding entry in the global `rulePool` has its refcount decremented.

#### Memory Reclamation (The "Arena Gap") - in POC
Currently, the Arena uses a **linear (bump) allocator** for simplicity and performance.
-   **Allocations:** Only move the tail pointer forward.
-   **Deletions:** Only decrement refcounts in the Go-side `rulePool`.
-   **Reclamation:** **No immediate reuse of arena memory occurs.**

> [!WARNING]
> Because deleted rules are not immediately overwritten, the arena memory usage monotonically increases until it reaches the 16MB limit. Memory is ONLY fully reclaimed and compacted upon **cilium-agent restart**, where the allocator state is rebuilt from scratch.

#### Future Improvements
-   **Free List Allocator:** Track freed blocks to allow reuse without restart.
-   **Compaction:** Background process to shift active rules and reclaim fragmented space.
-   **Large Page Support:** Optimize TLB pressure for very large arenas.

- **Fragmentation:** The agent-level `rulePool` tracks which arena blocks are logically "free", but the bump allocator does not reclaim them. A future "Free List" allocator or "Compactor" will address this fragmentation.

---

## Original Design Intent vs PoC Simplification

### Original Design: Multiple Rule Sets and Private Overrides

The overlay entry structure was designed with future extensibility in mind:

```
┌─────────────────────────────────────────────────────────────────────────┐
│              ORIGINAL DESIGN INTENT                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  MAX_SHARED_REFS (16) - Original Purpose:                               │
│  ─────────────────────────────────────────                              │
│  Allow an endpoint to reference MULTIPLE independent rule sets:         │
│                                                                         │
│  shared_handles[0]: CNP "web-access" rules                              │
│  shared_handles[1]: CNP "monitoring" rules                              │
│  shared_handles[2]: CCNP "dns-egress" rules                             │
│  shared_handles[3]: CCNP "default-deny" rules                           │
│  ...                                                                    │
│                                                                         │
│  This would allow:                                                      │
│  - Fine-grained sharing (share "dns-egress" across all pods)            │
│  - Independent policy updates (update "monitoring" without touching     │
│    "web-access")                                                        │
│  - Different policy sources to be tracked separately                    │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  MAX_PRIVATE_OVERRIDES (8) - Original Purpose:                          │
│  ─────────────────────────────────────────────                          │
│  Store endpoint-specific rules that CANNOT be shared:                   │
│                                                                         │
│  1. DENY RULES with higher precedence than shared ALLOW rules           │
│     - Deny rules need to override shared allows for specific endpoints  │
│     - Example: Shared "allow port 80" but this endpoint denies it       │
│                                                                         │
│  2. L7/PROXY RULES with endpoint-specific proxy ports                   │
│     - Each endpoint might have different proxy redirect ports           │
│     - Can't share because proxy_port varies per endpoint                │
│                                                                         │
│  3. SPILLOVER when shared_handles is full                               │
│     - If endpoint needs >16 rule sets, excess goes to private           │
│                                                                         │
│  Lookup order in BPF:                                                   │
│  1. Check private_overrides[] first (highest precedence)                │
│  2. Then check shared_handles[] via LPM trie                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### PoC Simplification: Single Combined Rule Set

For the initial PoC/Phase 3 implementation, we simplified:

```
┌─────────────────────────────────────────────────────────────────────────┐
│              POC SIMPLIFICATION                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Current Implementation:                                                │
│  ───────────────────────                                                │
│  - Agent PRE-COMBINES all policies before calling SyncEndpointOverlay() │
│  - Only 1 shared_ref is used (all rules in single rule_set)             │
│  - isPrivate is always FALSE (no private overrides)                     │
│  - Deny rules are included in the shared rule_set (BPF handles          │
│    precedence via LPM prefix matching)                                  │
│                                                                         │
│  Why This Works:                                                        │
│  ───────────────                                                        │
│  - LPM trie naturally handles deny/allow precedence                     │
│  - More specific rules (longer prefix) win over less specific           │
│  - Deny with full port match beats Allow with wildcard port             │
│                                                                         │
│  Code Evidence:                                                         │
│  ──────────────                                                         │
│  // pkg/maps/policymap/sharedmanager.go:128                             │
│  isPrivate := false  // Always false in current implementation          │
│                                                                         │
│  // pkg/maps/policymap/sharedmanager.go:184-187                         │
│  var finalSharedHandles []uint32                                        │
│  if groupID > 0 {                                                       │
│      finalSharedHandles = append(finalSharedHandles, groupID)  //Only 1 │
│  }                                                                      │
│                                                                         │
│  Future Enhancement Opportunity:                                        │
│  ───────────────────────────────                                        │
│  - Split policies by source (CNP vs CCNP) → multiple shared_refs        │
│  - Move deny rules to private_overrides for explicit precedence         │
│  - Use private_overrides for endpoint-specific proxy redirects          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Status - Phase 3

**IMPORTANT:** The current PoC implementation is functional but simplified compared to the full design intent:
- **Single Shared Reference:** All policies matching an endpoint are pre-combined into a single rule set by the agent. Only one entry in `shared_handles` is used.
- **Native Pointer Optimization (Address Space 1):** Global `__arena` variables are used, allowing direct native pointer access to arena memory without helper calls or map lookups (relocated by loader).
- **No Private Overrides:** `isPrivate` is always set to `false`. Private overrides are reserved for future use (e.g., endpoint-specific proxy redirects).
- **Linear Allocation:** Arena memory uses a linear allocator without reclamation. Memory "leaked" via policy churn is only recovered on agent restart.
- **Manual Cleanup:** Legacy per-endpoint BPF maps are not automatically deleted from `bpffs` during the upgrade; manual cleanup or node reboot is required.
- **Arena-Only Mode:** `pkg/maps/policymap/cell.go` implements an `arenaOnly` mode that skips creating legacy BPF maps entirely when arena is enabled, ensuring clean separation.

---

## PoC Optimizations

The PoC includes several performance optimizations that significantly reduce overhead for common operations.

### 1. Incremental Policy Updates

When an endpoint's policy changes, the system avoids full rebuilds when possible.

```
┌─────────────────────────────────────────────────────────────────────────┐
│              INCREMENTAL UPDATE DECISION FLOW                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  UpdateEndpointRules(epID, newRules) called                             │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ 1. Compute xxhash64 of newRules                                 │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ 2. CASE: Exact hash match exists?                               │    │
│  │    ─────────────────────────────                                │    │
│  │    YES → Reuse existing RuleSetID                               │    │
│  │          - Increment refcount                                   │    │
│  │          - Release old RuleSetID if different                   │    │
│  │          - FASTEST PATH: 0 BPF operations                       │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                              │ NO                                       │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ 3. CASE: Endpoint is sole owner of current RuleSetID?           │    │
│  │    ─────────────────────────────────────────────────            │    │
│  │    YES → Update in-place (incremental)                          │    │
│  │          - Compute diff: added, removed, modified rules         │    │
│  │          - Delete removed entries from LPM trie                 │    │
│  │          - Add new entries to LPM trie                          │    │
│  │          - EFFICIENT: Only changed rules written                │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                              │ NO                                       │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ 4. FALLBACK: Allocate new RuleSetID                             │    │
│  │    ──────────────────────────────                               │    │
│  │    - Allocate new rule_set_id                                   │    │
│  │    - Write all rules to LPM trie + arena                        │    │
│  │    - Release old RuleSetID (decrement refcount)                 │    │
│  │    - FULL REBUILD: All rules written                            │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Code Reference:** `pkg/maps/policymap/rule_set_allocator.go:UpdateEndpointRules()`

**Diff Computation:**

```go
// diffSharedLPMRules computes changes between old and new rule sets
func diffSharedLPMRules(old, new []SharedLPMRule) (added, removed []SharedLPMRule, modified []modifiedRule) {
    // Build map of old rules by key (excluding RuleSetID)
    oldMap := make(map[ruleKeyWithoutRuleSetID]SharedLPMRule)
    for _, r := range old {
        oldMap[keyWithoutRuleSetID(r)] = r
    }

    // Find added and modified
    for _, r := range new {
        if oldRule, exists := oldMap[keyWithoutRuleSetID(r)]; exists {
            if !sharedLPMRulesEqual(oldRule, r) {
                modified = append(modified, modifiedRule{old: oldRule, new: r})
            }
            delete(oldMap, keyWithoutRuleSetID(r))
        } else {
            added = append(added, r)
        }
    }

    // Remaining in oldMap are removed
    for _, r := range oldMap {
        removed = append(removed, r)
    }
    return
}
```

**Performance Impact:**

| Scenario | Legacy | Arena (Full Rebuild) | Arena (Incremental) |
|----------|--------|---------------------|---------------------|
| No change | N writes | 0 ops | 0 ops |
| 1 rule added | N+1 writes | N+1 writes | 1 write |
| 1 rule removed | N-1 writes | N-1 writes | 1 delete |
| 10% rules changed | ~N writes | ~N writes | ~0.1N ops |

---

### 2. Per-Rule Deduplication (Arena Level)

Beyond rule set deduplication across endpoints, the arena allocator deduplicates individual rules by their verdict data.

```
┌─────────────────────────────────────────────────────────────────────────┐
│              PER-RULE DEDUPLICATION IN ARENA                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Scenario: Two different rule sets with overlapping verdicts            │
│                                                                         │
│  RuleSet A (EP 701):                                                    │
│    Rule 1: Allow TCP/80   → verdict_hash = 0xABCD                       │
│    Rule 2: Allow TCP/443  → verdict_hash = 0xBCDE                       │
│    Rule 3: Deny  UDP/53   → verdict_hash = 0xCDEF                       │
│                                                                         │
│  RuleSet B (EP 702):                                                    │
│    Rule 4: Allow TCP/80   → verdict_hash = 0xABCD  ◄── SAME AS Rule 1   │
│    Rule 5: Allow TCP/8080 → verdict_hash = 0xBCDE  ◄── SAME AS Rule 2   │
│                                                                         │
│  WITHOUT Per-Rule Dedup:                                                │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │ Arena Memory: [Rule1][Rule2][Rule3][Rule4][Rule5] = 5 entries  │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                         │
│  WITH Per-Rule Dedup (Current Implementation):                          │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │ Arena Memory: [Rule1][Rule2][Rule3] = 3 entries                │     │
│  │                                                                │     │
│  │ rulePool map:                                                  │     │
│  │   0xABCD → {arenaOffset: 0, refcount: 2}   ◄── Shared!         │     │
│  │   0xBCDE → {arenaOffset: 12, refcount: 2}  ◄── Shared!         │     │
│  │   0xCDEF → {arenaOffset: 24, refcount: 1}                      │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                         │
│  Memory Saved: 2 entries × 12 bytes = 24 bytes (40% reduction)          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Code Reference:** `pkg/maps/policymap/arena_allocator.go:WriteRulesToSharedLPM()`

```go
// Inside WriteRulesToSharedLPM
for i, rule := range rules {
    // Compute hash of rule DATA (verdict fields only)
    ruleHash := computeRuleHash(rule)

    if existing, ok := a.rulePool[ruleHash]; ok {
        // REUSE: Same verdict already in arena
        arenaOffset = existing.arenaOffset
        a.rulePool[ruleHash] = rulePoolEntry{
            arenaOffset: existing.arenaOffset,
            refcount:    existing.refcount + 1,
        }
        deduplicatedEntries++
    } else {
        // NEW: Allocate in arena
        arenaOffset = a.nextArenaOff
        // Write entry to arena memory...
        a.rulePool[ruleHash] = rulePoolEntry{arenaOffset, 1}
        a.nextArenaOff += ArenaPolicyEntrySize
        newArenaEntries++
    }
}
```

**What Gets Hashed (Verdict Fields Only):**
- `ProxyPort` (2 bytes)
- `Deny` flag (1 bit)
- `AuthType` (7 bits)
- `HasExplicit` (1 bit)
- `Precedence` (4 bytes)
- `Cookie` (4 bytes)

**What's NOT Hashed (Varies Per Rule):**
- `RuleSetID` - Different per rule set
- `Identity` - Different per remote peer
- `Protocol`, `Port` - Key fields, not verdict

---

### 3. Batch LPM Trie Updates

When writing multiple rules, the system uses batch operations when supported by the kernel.

```
┌─────────────────────────────────────────────────────────────────────────┐
│              BATCH VS INDIVIDUAL LPM UPDATES                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Individual Updates (Fallback):                                         │
│  ───────────────────────────────                                        │
│  for each rule:                                                         │
│      syscall(BPF_MAP_UPDATE_ELEM, lpm_fd, &key, &value)                 │
│                                                                         │
│  Overhead: N syscalls for N rules                                       │
│  Latency: ~1µs per syscall × N                                          │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  Batch Updates (When Supported):                                        │
│  ───────────────────────────────                                        │
│  syscall(BPF_MAP_UPDATE_BATCH, lpm_fd, keys[], values[], count)         │
│                                                                         │
│  Overhead: 1 syscall for N rules                                        │
│  Latency: ~10µs total (amortized)                                       │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  Performance Comparison (100 rules):                                    │
│  ┌─────────────────────┬───────────────┬────────────────┐               │
│  │ Method              │ Syscalls      │ Latency        │               │
│  ├─────────────────────┼───────────────┼────────────────┤               │
│  │ Individual          │ 100           │ ~100µs         │               │
│  │ Batch               │ 1             │ ~15µs          │               │
│  │ Speedup             │ 100x          │ ~6.7x          │               │
│  └─────────────────────┴───────────────┴────────────────┘               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Code Reference:** `pkg/maps/policymap/arena_allocator.go:WriteRulesToSharedLPM()`

```go
// Phase 2: Write to LPM trie using batch operations when available
if len(keys) > 1 && hasBatchUpdateSupport(lpmMap) {
    _, err := lpmMap.BatchUpdate(keys, values, &ciliumebpf.BatchOptions{
        ElemFlags: uint64(ciliumebpf.UpdateAny),
    })
    if err == nil {
        batchUsed = true
    }
    // Fall back to individual updates on error
}

if !batchUsed {
    for i := range keys {
        lpmMap.Update(keys[i], values[i], 0)
    }
}
```

**Kernel Requirements:**
- Batch operations require Linux 5.6+ for hash maps
- LPM trie batch support varies by kernel version
- Automatic fallback ensures compatibility

---

### Combined Optimization Impact

When all optimizations work together:

```
┌─────────────────────────────────────────────────────────────────────────┐
│              OPTIMIZATION STACK EXAMPLE                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Scenario: EP 701 policy changes from [80,443] to [80,443,8080]         │
│                                                                         │
│  Step 1: Compute hash of new rules                                      │
│          Hash = 0x1234 (different from old 0x5678)                      │
│                                                                         │
│  Step 2: Check if hash exists → NO (new combination)                    │
│                                                                         │
│  Step 3: Check if sole owner → YES (refcount == 1)                      │
│          → Use INCREMENTAL UPDATE                                       │
│                                                                         │
│  Step 4: Compute diff                                                   │
│          - Added: [8080]                                                │
│          - Removed: []                                                  │
│          - Modified: []                                                 │
│                                                                         │
│  Step 5: Write new rule to arena                                        │
│          - Check rulePool for Allow TCP/8080 verdict                    │
│          - If exists → REUSE arena offset (per-rule dedup)              │
│          - If not → Allocate 12 bytes in arena                          │
│                                                                         │
│  Step 6: Update LPM trie                                                │
│          - Only 1 entry to add                                          │
│          - Individual update (batch not needed for 1 entry)             │
│                                                                         │
│  Result: 1 LPM write + possibly 0 arena bytes (if verdict reused)       │
│  vs Legacy: 3 LPM writes (delete all, write all)                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Benchmark & Scale Results

The Arena Shared Policy Map architecture has been rigorously evaluated using both synthetic scale models (pkg/maps/policymap/scale_test.go) and end-to-end Kubernetes benchmarks (test/arena-benchmark).

### Scale Analysis (Synthetic Model)

The following results compare legacy per-endpoint maps against arena shared maps across various cluster sizes, assuming a mix of shared and unique policies.

#### Memory Savings Summary

| Scenario | Endpoints | Rules/EP | Legacy Mem | Arena Mem | Savings | Dedup Ratio |
|----------|-----------|----------|------------|-----------|---------|-------------|
| Small    | 100       | 10       | 19.5 KB    | 20.7 KB   | -6.0%   | 20.0x       |
| Medium   | 500       | 20       | 195.3 KB   | 102.3 KB  | 47.6%   | 50.0x       |
| Large    | 1,000     | 50       | 976.6 KB   | 218.8 KB  | 77.6%   | 50.0x       |
| XL       | 2,000     | 100      | 3.8 MB     | 507.8 KB  | 87.0%   | 40.0x       |

*Note: For very small clusters, the fixed overhead of the shared infrastructure (overlay + shared trie) may exceed the savings from 100 small maps, but scaling is sub-linear thereafter.*

#### Operational Speedup

| Metric | Legacy (Per-EP) | Arena (Shared) | Speedup |
|--------|-----------------|----------------|---------|
| **Endpoint Add** | ~1ms (Map Create + 100 writes) | ~66µs (Hash + Overlay write) | **15.1x** |
| **Endpoint Remove** | ~100µs (Unpin + Close) | ~20µs (Refcount Dec) | **5.0x** |
| **Policy Update** | ~500µs (100 writes) | ~5µs (1 write) | **100x** |
| **Hash Calc** | ~17µs (SHA256) | ~16µs (xxhash) | 1.0x |

---

### End-to-End Benchmark Results (February 2026)

Verified on a 3-node Kind cluster with 100 policies applied to test workloads. Results compare the initial Arena PoC (Map-based config) against the latest JIT-optimized Arena implementation.

#### Data Plane Performance

| Metric | Legacy Mode | Arena (Map-based) | Arena (JIT-optimized) | Delta (JIT vs Legacy) |
|--------|-------------|-------------------|-----------------------|-----------------------|
| **Transaction Rate** | 15,613 tps | 13,996 tps | **15,008 tps** | -3.8% |
| **Mean Latency** | 63.7 µs | 70.7 µs | **66.6 µs** | +4.5% |
| **P99 Latency** | 191 µs | 207 µs | **199 µs** | +4.1% |
| **Throughput** | 4.7 Gbps | 2.8 Gbps | **4.6 Gbps** | -2.1% |

*Analysis: The transition from map-lookup based configuration to JIT-constant injection resolved the primary throughput bottleneck observed in Phase 3. The system now operates at ~97% efficiency compared to legacy per-endpoint maps while providing 87% memory savings.*

#### JIT-Constant Optimization

To minimize the lookup overhead, the `arena_base_addr` is now injected as a BPF JIT constant using the `DECLARE_CONFIG` macro.

**Benefits:**
- **Zero Map Lookups:** Removes the `map_lookup_elem(&cilium_arena_cfg, ...)` call from the packet fast-path.
- **Instruction Level Injection:** The Cilium agent patches the BPF bytecode with the 64-bit arena address (fixed at `0x10000000000`) at load time.
- **Throughput Gains:** Increased same-node throughput by **62.7%** compared to the map-based approach.

#### Memory Efficiency (Active Cluster)

| Map Type | Legacy Map Count | Arena Map Count | Legacy Bytes | Arena Bytes |
|----------|------------------|-----------------|--------------|-------------|
| Policy Maps | 100+ | 1 (Shared) | ~22 MB | 0 B |
| Overlay Map | 0 | 1 | 0 B | ~264 KB |
| **Total** | **100+** | **2** | **~22 MB** | **~264 KB** |

**Total Memory Reduction: >98% for policy structures in active tests.**

---

## Benchmark Methodology

This section documents what metrics are measured, how they are measured, and the tools used for benchmarking the Arena Shared Policy Map architecture.

### What We Measure

The benchmark suite measures five key performance dimensions:

#### 1. Memory Usage
- **BPF Map Memory**: Total bytes locked in kernel memory for policy maps
- **Per-map overhead**: Memory consumed by each BPF map structure
- **Policy entry memory**: Memory per policy rule (key + value)
- **Arena shared memory**: Memory used by the shared arena region
- **Deduplication ratio**: Entries saved through rule sharing

**How we measure:**
```bash
# Inside Cilium pod - get BPF map memory usage
bpftool map list -j | jq '.[] | select(.name | contains("policy") or contains("arena")) | {name, bytes_memlock}'

# Via measure-bpf-memory.sh script:
bpftool map show id <map_id>              # Individual map sizes
cilium-dbg bpf policy get --all | wc -l   # Policy entry counts
cat /proc/meminfo | grep -E "Mapped|Shmem" # System memory stats
```

#### 2. Network Latency (TCP Request/Response)
- **Mean latency**: Average round-trip time for TCP request/response
- **Min/Max latency**: Latency range showing consistency
- **P50/P99 latency**: Percentile latencies for tail behavior
- **Transactions/sec**: Request throughput

**How we measure:**
```bash
# Using netperf TCP_RR (Request/Response) test - 3 iterations of 30 seconds
netperf -H <server-ip> -t TCP_RR -l 30 -- -o min_latency,max_latency,mean_latency,P50_LATENCY,P99_LATENCY
```

#### 3. Network Throughput (TCP Stream)
- **Mbps/Gbps**: Raw TCP throughput
- **Socket buffer sizes**: Send/receive buffer configuration

**How we measure:**
```bash
# Using netperf TCP_STREAM test
netperf -H <server-ip> -t TCP_STREAM -l 30

# Using iperf3 for validation
iperf3 -c <server-ip> -t 30 -J
```

#### 4. Policy Lookup Stress
- **BPF program run counts**: Number of times policy programs execute
- **Policy verdict metrics**: Allow/deny decision counts
- **Program runtime statistics**: CPU time spent in BPF programs

**How we measure:**
```bash
# BPF program statistics
bpftool prog list | grep -A2 "cil_"

# Cilium metrics
cilium-dbg metrics list | grep -i policy
```

#### 5. Policy Update Performance
- **Hash computation time**: SHA256 (legacy) vs xxhash64 (arena)
- **Diff computation time**: Time to compute incremental updates
- **BPF write latency**: Time per map update operation
- **Endpoint churn cost**: Time to add/remove endpoints

### Unit-Level Benchmarks (Go Tests)

Go-based micro-benchmarks are available in `pkg/maps/policymap/scale_test.go`:

#### Hash Computation Comparison
```bash
# Compare legacy SHA256 vs arena xxhash64
go test -bench=BenchmarkScaleHash -benchtime=3s ./pkg/maps/policymap/
```

#### Scale Scenarios Tested

| Scenario | Endpoints | Rules/Policy | Unique Policies | Identity Range |
|----------|-----------|--------------|-----------------|----------------|
| Small    | 100       | 10           | 5               | 50             |
| Medium   | 500       | 20           | 10              | 100            |
| Large    | 1,000     | 50           | 20              | 200            |
| XL       | 2,000     | 100          | 50              | 500            |

#### Available Analysis Tests

```bash
# Run all scale analysis tests (no BPF required - pure Go computation)
go test -run=TestScaleAnalysis -v ./pkg/maps/policymap/

# Individual analysis tests:
go test -run=TestScaleAnalysisMemoryDedup -v ./pkg/maps/policymap/        # Memory & deduplication
go test -run=TestScaleAnalysisPolicyUpdateLatency -v ./pkg/maps/policymap/ # Update latency breakdown
go test -run=TestScaleAnalysisEndpointChurn -v ./pkg/maps/policymap/       # Endpoint add/remove cost
go test -run=TestScaleAnalysisPolicyChurn -v ./pkg/maps/policymap/         # Policy update cost
go test -run=TestScaleAnalysisSummary -v ./pkg/maps/policymap/             # Summary table

# Run all benchmarks with memory allocation stats
go test -bench=BenchmarkScale -benchmem -benchtime=3s -count=3 ./pkg/maps/policymap/
```

#### Arena Allocator Benchmarks (Requires Linux 6.4+)
```bash
# Unit tests for arena allocator
go test -run=TestArenaAllocator -v ./pkg/maps/policymap/

# Benchmark arena allocation performance
go test -bench=BenchmarkArenaAllocator -benchtime=3s ./pkg/maps/policymap/
```

### End-to-End Benchmark Environment

The full benchmark (`test/arena-benchmark/benchmark.sh`) uses:

| Component | Configuration |
|-----------|---------------|
| **Kubernetes** | kind cluster with 3 nodes (1 control-plane, 2 workers) |
| **CNI** | Cilium built from local source |
| **Network mode** | VXLAN tunnel |
| **Test pods** | netperf client/server, iperf3 client/server |
| **Pod placement** | Anti-affinity ensures cross-node traffic |
| **Policy count** | 100 CiliumNetworkPolicies (configurable) |

**Running the benchmark:**
```bash
cd test/arena-benchmark
./benchmark.sh --both   # Test both arena and legacy modes
./benchmark.sh --arena  # Test arena mode only
./benchmark.sh --legacy # Test legacy mode only
```

### Metrics Interpretation

| Metric | Good Value | Warning | Critical |
|--------|------------|---------|----------|
| **Memory savings** | >50% | <30% | <0% (regression) |
| **Latency delta** | <5% regression | 5-15% regression | >15% regression |
| **Throughput delta** | <2% regression | 2-5% regression | >5% regression |
| **Deduplication ratio** | >10x | 5-10x | <5x |
| **Hash speedup (xxhash vs SHA256)** | >5x | 3-5x | <3x |

### Related Test Files

| File | Purpose |
|------|---------|
| `test/arena-benchmark/benchmark.sh` | Full end-to-end benchmark with Kubernetes |
| `test/arena-benchmark/measure-bpf-memory.sh` | BPF memory measurement script |
| `test/arena-benchmark/analyze-results.py` | Results parser and report generator |
| `pkg/maps/policymap/scale_test.go` | Scale analysis and Go benchmarks |
| `pkg/maps/policymap/arena_allocator_test.go` | Arena allocator unit tests |
| `pkg/maps/policymap/arena_allocator_bench_test.go` | Arena allocator benchmarks |

---

## Recommended Additional Tests & Benchmarks

To further validate the robustness and performance of the Arena Shared Policy Map architecture, the following additional test scenarios are recommended:

### 1. Port Range Scale Testing
The current benchmarks primarily use exact port matches. Benchmarking large sets of port ranges (e.g., `8000-9000`) will specifically exercise the **Shared LPM Trie** and its prefix matching logic, which should significantly outperform legacy hash maps that require one entry per port.

### 2. High Remote Identity Cardinality
Stress test the **sequential binary search** in BPF by applying policies that match thousands of unique remote identities. This will help determine the practical limits of the current lookup algorithm before latency becomes prohibitive.

### 3. Precedence & Conflict Resolution
Implement automated tests that generate overlapping `ALLOW` and `DENY` rules with varying prefix lengths to verify that the LPM trie and BPF fallback logic consistently resolve to the correct decision, matching legacy behavior.

### 4. Egress Policy Benchmarking
While ingress is the primary focus of current benchmarks, egress policy lookups should be measured to ensure there are no performance regressions in the egress path, especially for multi-homed endpoints.

### 5. Multi-RuleSet (Phase 4) Simulation
Simulate scenarios where endpoints reference multiple independent rule sets (e.g., one for CNP, one for CCNP) to validate the `MAX_SHARED_REFS` looping logic and its impact on BPF instruction count and verifier complexity.

---

### Memory Efficiency Verification

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    MEMORY VERIFICATION RESULTS                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Per-Endpoint Maps (cilium_policy_v*): 0 bytes                          │
│  ────────────────────────────────────────────────                       │
│  All per-endpoint policy maps have been completely eliminated.          │
│  Policy state is now managed entirely through the shared arena.         │
│                                                                         │
│  Shared Arena Maps (Active):                                            │
│  ─────────────────────────────                                          │
│  • cilium_policy_o (overlay)  - Endpoint ID → Policy references         │
│  • cilium_policy_s (shared)   - Shared LPM trie for rule lookup         │
│  • cilium_policy_a (arena)    - Shared memory for rule data             │
│                                                                         │
│  Identity Handling (Verified):                                          │
│  ───────────────────────────────                                        │
│  • Pod identities: Correctly routed through arena lookup                │
│  • Host identity: Allowed via IS_BPF_HOST fallback                      │
│  • Remote-node (ID 6): Allowed via EFFECTIVE_EP_ID == 0 fallback        │
│  • Health endpoints: Allowed via wildcard rules for policy-disabled EPs │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Key Technical Insight: Arena vs Legacy Lookup Differences

```
┌─────────────────────────────────────────────────────────────────────────┐
│                 LOOKUP BEHAVIOR COMPARISON                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  LEGACY MODE (Per-Endpoint Map):                                        │
│  ─────────────────────────────────                                      │
│  1. Lookup in `cilium_policy_<id>` with actual identity.                │
│  2. If no match, lookup with identity=0 (L4-only/wildcard).             │
│  3. Loop over port ranges if needed (in BPF).                           │
│                                                                         │
│  ARENA MODE (Shared Map + Overlay):                                     │
│  ──────────────────────────────────                                     │
│  1. Lookup `cilium_policy_o` with Endpoint ID → Get RuleSet IDs.        │
│  2. For each RuleSet ID (max 4):                                        │
│     a. Lookup `cilium_policy_s` with {RuleSetID, Identity, Port/Proto}  │
│     b. Lookup `cilium_policy_s` with {RuleSetID, 0, Port/Proto}         │
│     c. Kernel handles LPM prefix matching for ports (No BPF loop).      │
│                                                                         │
│  KEY DIFFERENCE:                                                        │
│  - Legacy: O(Rules per Endpoint) memory. Single map lookup.             │
│  - Arena:  O(Unique Rules) memory. Multiple map lookups (2 per RuleSet).│
│                                                                         │
│  The trade-off is slightly more CPU (map lookups) for massive Memory    │
│  savings and scalability.                                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### What Was Verified

| Feature | Status | Notes |
|---------|--------|-------|
| Same-node pod-to-pod | ✓ Verified | 4.6 Gbps throughput (JIT-opt) |
| Cross-node pod-to-pod | ✓ Verified | 2.5 Gbps throughput |
| Service IP load balancing | ✓ Verified | 8.3 Gbps via iperf3 |
| Port Range Ingress (8000-9000) | ✓ Verified | Correctly allowed ranges and denied non-range ports |
| CCNP Overlap | ✓ Verified | Validated multi-policy allow/deny precedence |
| Health check connectivity | ✓ Verified | 3/3 nodes reachable |
| Policy enforcement (pods) | ✓ Verified | Rules correctly applied |
| Host endpoint handling | ✓ Verified | Via IS_BPF_HOST fallback |
| Overlay program handling | ✓ Verified | Via EFFECTIVE_EP_ID == 0 |
| Policy-disabled endpoints | ✓ Verified | Via wildcard allow rules |
| Memory deduplication | ✓ Verified | Per-EP maps = 0 bytes |
| Rule set reference counting | ✓ Verified | Proper allocation/deallocation |

---

## Alternative Approaches Tried (Rejected)

During development, several alternative architectures were explored before arriving at the current LPM trie-based design. Each was rejected due to BPF verifier limitations or performance concerns.

```
┌────────────────────────────────────────────────────────────────────────┐
│              REJECTED APPROACH #1: RULE SET → RULE ID MAPPING          │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  CONCEPT:                                                              │
│  ─────────                                                             │
│  Store a mapping from rule_set_id to an array of rule_ids, then        │
│  iterate through rule_ids to find matching rules.                      │
│                                                                        │
│  Data Structures:                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  rule_set_map: rule_set_id → [rule_id_1, rule_id_2, ..., rule_id_n] │
│  │  rule_map: rule_id → policy_entry                                   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                        │
│  BPF Pseudocode:                                                       │
│  struct rule_id_array *rules = map_lookup(&rule_set_map, &rule_set_id);│
│  for (int i = 0; i < rules->count; i++) {                              │
│      struct policy_entry *entry =map_lookup(&rule_map, &rules->ids[i]);│
│      if (matches(packet, entry)) return entry;                         │
│  }                                                                     │
│                                                                        │
│  WHY IT WAS REJECTED:                                                  │
│  ─────────────────────                                                 │
│  1. BPF VERIFIER LOOP LIMITS                                           │
│     - Verifier requires bounded loops with known iteration count       │
│     - Dynamic rules->count causes verifier rejection                   │
│     - Even with #pragma unroll, limits practical rule count            │
│                                                                        │
│  2. O(N) LOOKUP COMPLEXITY                                             │
│     - Must check every rule sequentially                               │
│     - With 100 rules: 100 map lookups per packet                       │
│     - Performance degrades linearly with policy complexity             │
│                                                                        │
│  3. NO PORT RANGE SUPPORT                                              │
│     - Exact match only, no prefix-based port ranges                    │
│     - Would need separate entries for each port in a range             │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│              REJECTED APPROACH #2: BINARY SEARCH IN ARENA               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  CONCEPT:                                                               │
│  ─────────                                                              │
│  Store rules sorted by (identity, proto, port) in arena memory.         │
│  Use binary search to find matching rule in O(log N) time.              │
│                                                                         │
│  Data Structures:                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  Arena Layout (sorted):                                         │    │
│  │  [0]: {identity=100, proto=6, port=22, action=ALLOW}            │    │
│  │  [1]: {identity=100, proto=6, port=80, action=ALLOW}            │    │
│  │  [2]: {identity=100, proto=6, port=443, action=ALLOW}           │    │
│  │  [3]: {identity=200, proto=17, port=53, action=ALLOW}           │    │
│  │  ...                                                            │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  BPF Pseudocode:                                                        │
│  int lo = 0, hi = rule_count;                                           │
│  while (lo < hi) {                                                      │
│      int mid = (lo + hi) / 2;                                           │
│      struct rule *r = arena_base + mid * sizeof(rule);                  │
│      int cmp = compare(packet, r);                                      │
│      if (cmp == 0) return r;                                            │
│      if (cmp < 0) hi = mid;                                             │
│      else lo = mid + 1;                                                 │
│  }                                                                      │
│                                                                         │
│  WHY IT WAS REJECTED:                                                   │
│  ─────────────────────                                                  │
│  1. BPF VERIFIER REJECTS DYNAMIC LOOPS                                  │
│     - "while (lo < hi)" has unknown iteration count                     │
│     - Verifier cannot prove termination                                 │
│     - Even with max iterations hint, verifier is conservative           │
│                                                                         │
│  2. INSERTION PERFORMANCE                                               │
│     - Adding a rule requires re-sorting entire array                    │
│     - O(N) memory moves for each policy update                          │ 
│     - Frequent policy changes become expensive                          │
│                                                                         │
│  3. NO WILDCARD/RANGE SUPPORT                                           │
│     - Binary search requires exact key comparison                       │
│     - "Any port" or "port range 8000-9000" doesn't fit                  │
│     - Would need multiple lookups for partial matches                   │
│                                                                         │
│  4. ARENA POINTER ARITHMETIC COMPLEXITY                                 │
│     - BPF verifier is strict about arena pointer bounds                 │
│     - mid * sizeof(rule) needs careful bounds checking                  │
│     - Each iteration adds verifier complexity                           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│              REJECTED APPROACH #3: HASH MAP WITH WILDCARDS              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  CONCEPT:                                                               │
│  ─────────                                                              │
│  Use multiple hash map lookups with progressively more wildcards        │
│  to find the most specific matching rule.                               │
│                                                                         │
│  Lookup Order:                                                          │
│  1. lookup(identity=X, proto=TCP, port=80)    // Exact match            │
│  2. lookup(identity=X, proto=TCP, port=ANY)   // Any port               │
│  3. lookup(identity=X, proto=ANY, port=ANY)   // Any proto/port         │
│  4. lookup(identity=ANY, proto=ANY, port=ANY) // Default rule           │
│                                                                         │
│  WHY IT WAS REJECTED:                                                   │
│  ─────────────────────                                                  │
│  1. MULTIPLE MAP LOOKUPS PER PACKET                                     │
│     - 4+ lookups in worst case (no exact match)                         │
│     - Each lookup has ~100ns overhead                                   │
│     - Cumulative latency unacceptable for fast path                     │
│                                                                         │
│  2. NO PORT RANGE SUPPORT                                               │
│     - Hash maps require exact keys                                      │
│     - "ports 8000-9000" would need 1000 entries                         │
│     - Memory explosion for port ranges                                  │
│                                                                         │
│  3. PRECEDENCE COMPLEXITY                                               │
│     - Must check in specific order for correct precedence               │
│     - Deny rules need separate handling                                 │
│     - Code becomes complex and error-prone                              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│              REJECTED APPROACH #4: BLOOM FILTER + EXACT LOOKUP          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  CONCEPT:                                                               │
│  ─────────                                                              │
│  Use a bloom filter for fast "definitely not" check, then exact         │
│  lookup only if bloom filter says "maybe".                              │
│                                                                         │
│  WHY IT WAS REJECTED:                                                   │
│  ─────────────────────                                                  │
│  1. FALSE POSITIVES REQUIRE FULL LOOKUP ANYWAY                          │
│     - Bloom filter only helps negative case                             │
│     - Most packets ARE allowed (match exists)                           │
│     - Doesn't help the common case                                      │
│                                                                         │
│  2. STILL NEED EXACT LOOKUP MECHANISM                                   │
│     - Bloom filter doesn't return the policy entry                      │
│     - Need another data structure for actual lookup                     │
│     - Adds complexity without solving core problem                      │
│                                                                         │
│  3. NO PORT RANGE SUPPORT                                               │
│     - Same problem as hash maps                                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│              WHY LPM TRIE IS THE RIGHT SOLUTION                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  The current LPM (Longest Prefix Match) trie approach solves all        │
│  the problems that rejected other approaches:                           │
│                                                                         │
│  1. SINGLE MAP LOOKUP                                                   │
│     ─────────────────────                                               │
│     - O(1) lookup via kernel's native LPM trie implementation           │
│     - No loops in BPF code → verifier is happy                          │
│     - Consistent performance regardless of rule count                   │
│                                                                         │
│  2. NATIVE PORT RANGE SUPPORT                                           │
│     ─────────────────────────                                           │
│     - Prefix length encodes port ranges naturally                       │
│     - port=80 (exact): prefix=24 (8 proto + 16 port bits)               │
│     - port=0 (any): prefix=8 (8 proto bits only)                        │
│     - port range via MSB matching (e.g., 8000-8255 = prefix 8+8)        │
│                                                                         │
│  3. AUTOMATIC PRECEDENCE                                                │
│     ────────────────────────                                            │
│     - LPM returns LONGEST matching prefix                               │
│     - More specific rules automatically win                             │
│     - Deny on port 80 (prefix=24) beats Allow any port (prefix=8)       │
│                                                                         │
│  4. VERIFIER-FRIENDLY                                                   │
│     ────────────────────                                                │
│     - No loops in user BPF code                                         │
│     - Single map_lookup_elem() call                                     │
│     - Kernel handles trie traversal internally                          │
│     - Bounded instruction count, predictable verification               │
│                                                                         │
│  5. NO PERFORMANCE DEGRADATION                                          │
│     ──────────────────────────                                          │
│     - Same O(1) lookup as legacy per-endpoint hash maps                 │
│     - Actually faster for port ranges (1 lookup vs N lookups)           │
│     - Memory access pattern is cache-friendly                           │
│                                                                         │
│  PERFORMANCE COMPARISON:                                                │
│  ────────────────────────                                               │
│  ┌────────────────────┬───────────────┬───────────────────────────┐     │
│  │ Approach           │ Lookup Time   │ Verifier Status           │     │
│  ├────────────────────┼───────────────┼───────────────────────────┤     │
│  │ Rule ID iteration  │ O(N) ~1-10μs  │ REJECTED (unbounded loop) │     │
│  │ Binary search      │ O(log N) ~500ns│ REJECTED (dynamic loop)  │     │
│  │ Multi-hash lookup  │ O(K) ~400ns   │ OK but slow               │     │
│  │ LPM Trie (current) │ O(1) ~100ns   │ OK and fast               │     │
│  └────────────────────┴───────────────┴───────────────────────────┘     │
│                                                                         │
│  CODE EVIDENCE (current working solution):                              │
│  ──────────────────────────────────────────                             │
│  // bpf/lib/policy.h - Single LPM lookup, no loops                      │
│  struct shared_policy_value *v =map_lookup_elem(&cilium_policy_s, &key);│
│  if (v) {                                                               │
│      // Direct arena access via offset                                  │
│      struct policy_entry *entry = arena_base + v->arena_offset;         │
│      // Apply policy - no iteration needed                              │
│  }                                                                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## cilium/ebpf Package Changes for Arena Support

The arena feature required modifications to the `github.com/cilium/ebpf` library:

### 1. Arena Map Type Support

```go
// vendor/github.com/cilium/ebpf/types.go
const (
    // Arena - Sparse shared memory region between a BPF program and user space.
    Arena MapType = 33  // BPF_MAP_TYPE_ARENA
)
```

### 2. ELF Section Handling for Arena Variables

```go
// vendor/github.com/cilium/ebpf/elf_reader.go
func isArenaSection(name string) bool {
    // Handles .addr_space.1 sections for arena variables
}

case arenaSection:
    // Arena section contains global variables with __arena attribute.
    // These live in BPF_MAP_TYPE_ARENA memory and need to be relocated
    // to reference the arena map with the variable's offset.
```

### 3. Memory Mapping for Shared Access

```go
// vendor/github.com/cilium/ebpf/memory.go
func newMemory(fd, size int, addrHint uint64) (*Memory, error) {
    flags := unix.MAP_SHARED
    if addrHint != 0 {
        flags |= unix.MAP_FIXED  // For Arena's fixed address
        ptr, err = unix.MmapPtr(fd, 0, unsafe.Pointer(uintptr(addrHint)),
                                uintptr(size), unix.PROT_READ|unix.PROT_WRITE, flags)
    }

    // For MAP_FIXED mappings (Arena), we do not register a cleanup function.
    // These mappings are intended to be singleton/persistent for the process lifetime.
    if addrHint == 0 {
        mm.cleanup = runtime.AddCleanup(mm, memoryCleanupFunc(), b)
    }
}
```

### 4. MapExtra for Arena Address Hints

```go
// vendor/github.com/cilium/ebpf/map.go
case Arena:
    // For Arenas, MaxEntries denotes the maximum number of pages available to
    // the arena.
    // MapExtra acts as an address hint for Arena maps.
```

---

## Persistence and Agent Restart

How the arena architecture survives agent restarts:

```
┌─────────────────────────────────────────────────────────────────────────┐
│              PERSISTENCE MECHANISM                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. BPF MAP PINNING                                                     │
│  ───────────────────                                                    │
│  All maps are pinned to /sys/fs/bpf/tc/globals/                         │
│                                                                         │
│  - cilium_policy_a (arena)     → Pinned, survives restart               │
│  - cilium_policy_s (shared LPM)→ Pinned, survives restart               │
│  - cilium_policy_o (overlay)   → Pinned, survives restart               │
│  - cilium_arena_c (config)     → Pinned, stores arena base address      │
│  - cilium_arena_p (pointer)    → Pinned, stores arena pointer           │
│                                                                         │
│  2. ARENA MEMORY PERSISTENCE                                            │
│  ───────────────────────────────                                        │
│  Arena uses MAP_FIXED at address 0x10000000000 (1TB offset)             │
│                                                                         │
│  // pkg/maps/policymap/universal_maps.go:262-271                        │
│  addr := uintptr(0x10000000000)                                         │
│  r, _, errno := unix.Syscall6(unix.SYS_MMAP,                            │
│      addr,                                                              │
│      uintptr(size),                                                     │
│      uintptr(unix.PROT_READ|unix.PROT_WRITE),                           │
│      uintptr(unix.MAP_SHARED|unix.MAP_FIXED),                           │
│      uintptr(fd),                                                       │
│      0,                                                                 │
│  )                                                                      │
│                                                                         │
│  Why MAP_FIXED at specific address:                                     │
│  - BPF programs have the arena address compiled in                      │
│  - Agent must mmap at SAME address after restart                        │
│  - Prevents pointer invalidation                                        │
│                                                                         │
│  3. AGENT RESTART FLOW                                                  │
│  ─────────────────────                                                  │
│                                                                         │
│  Agent Startup:                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ 1. Try LoadRegisterMap() for each map                           │    │
│  │    - If exists: Reuse existing pinned map                       │    │
│  │    - If not: Create new map and pin                             │    │
│  │                                                                 │    │
│  │ 2. Mmap arena at fixed address                                  │    │
│  │    - If arena existed: Memory contents preserved                │    │
│  │    - If new: Initialize fresh                                   │    │
│  │                                                                 │    │
│  │ 3. RestoreEndpointOverlay() for each endpoint                   │    │
│  │    - REBUILD in-memory refcounts from pinned overlay map        │    │
│  │    - Register rule_set_ids back into the allocator              │    │
│  │    - NOTE: Refcounts are NOT persisted in BPF; they are purely  │    │
│  │      managed in-memory and reconstructed during restoration.    │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  4. KERNEL MEMORY GUARANTEES                                            │
│  ───────────────────────────────                                        │
│  - Pinned BPF maps survive process exit                                 │
│  - Arena memory is kernel-managed (not process memory)                  │
│  - MAP_SHARED ensures BPF and userspace see same memory                 │
│  - Page faults handled by kernel (touch memory to ensure allocation)    │
│                                                                         │
│  // pkg/maps/policymap/universal_maps.go:287-288                        │
│  // Touch the memory to ensure it's allocated in kernel.                │
│  ptr := (*uint16)(unsafe.Pointer(r))                                    │
│  *ptr = 0                                                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Comparison: Legacy vs Arena

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    FEATURE COMPARISON                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Feature              │ Legacy              │ Arena                     │
│  ─────────────────────┼─────────────────────┼────────────────────────── │
│  Memory per endpoint  │ O(Ref Rules)        │ O(1) (Fixed Overlay)      │
│  Rule deduplication   │ None                │ Per-Rule (Global Data)    │
│  Policy update        │ Per-endpoint writes │ Shared RuleSet (COW)      │
│  LPM port matching    │ Per-endpoint trie   │ Single shared trie        │
│  BPF map count        │ O(endpoints)        │ O(1) fixed global maps    │
│  Verifier complexity  │ Per-endpoint (High) │ Single program (Low)      │
│  Memory scaling       │ Linear O(N*M)       │ Sublinear O(UniqueRules)  │
│  Cleanup complexity   │ Simple (Map delete) │ Refcount management       │
│  Debugging            │ Direct map dump     │ Overlay → RuleSet dump    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```
---

## File Reference

### Implementation Files

| File | Purpose |
|------|---------|
| `bpf/lib/policy.h` | BPF policy lookup, map definitions, `policy_lookup_shared()` |
| `pkg/maps/policymap/sharedmap.go` | Go structs matching BPF, `OverlayEntryBPF`, `SharedLPMKey/Value` |
| `pkg/maps/policymap/sharedmapspec.go` | Overlay map creation and loading |
| `pkg/maps/policymap/sharedmanager.go` | `SyncEndpointOverlay()`, policy synchronization |
| `pkg/maps/policymap/arena_allocator.go` | Arena memory management, block allocation |
| `pkg/maps/policymap/rule_set_allocator.go` | Rule set hashing, deduplication, LPM entry management |
| `pkg/maps/policymap/universal_maps.go` | Arena and shared LPM trie initialization |
| `pkg/maps/policymap/cell.go` | Factory with `arenaOnly` mode |

### Test Files

| File | Purpose |
|------|---------|
| `pkg/maps/policymap/scale_test.go` | Scale analysis benchmarks, memory/latency comparisons |
| `pkg/maps/policymap/arena_allocator_test.go` | Arena allocator unit tests |
| `pkg/maps/policymap/arena_allocator_bench_test.go` | Arena allocator performance benchmarks |
| `pkg/maps/policymap/arena_e2e_test.go` | End-to-end arena integration tests |
| `pkg/maps/policymap/rule_set_allocator_test.go` | Rule set hashing and allocation tests |
| `pkg/maps/policymap/sharedmanager_test.go` | Shared manager unit tests |
| `pkg/maps/policymap/sharedmanager_restart_test.go` | Agent restart/restore tests |

### Benchmark Scripts

| File | Purpose |
|------|---------|
| `test/arena-benchmark/benchmark.sh` | Full end-to-end Kubernetes benchmark |
| `test/arena-benchmark/measure-bpf-memory.sh` | BPF memory measurement utility |
| `test/arena-benchmark/analyze-results.py` | Results parser and report generator |
| `test/arena-benchmark/quick-bpf-test.sh` | Quick BPF compilation verification |

---

## Debugging

### Dump Overlay Map

```bash
# List all overlay entries
bpftool map dump name cilium_policy_o

# Check specific endpoint
bpftool map lookup name cilium_policy_o key 0xbd 0x02 0x00 0x00  # EP 701
```

### Dump Shared LPM Trie

```bash
bpftool map dump name cilium_policy_s
```

### Check Arena Contents

```bash
# Arena is memory-mapped, use cilium CLI
cilium bpf policy get --arena
```

### Metrics to Monitor

```promql
# Spillover count (rules that didn't fit in shared refs)
cilium_policy_shared_map_entries{type="spillover"}

# Shared rule operations
cilium_policy_shared_map_ops{operation="add", outcome="success"}
cilium_policy_shared_map_ops{operation="delete", outcome="success"}

# Arena memory usage
cilium_bpf_arena_bytes_used{map="cilium_policy_a"}
```

---

## Known Limitations

1. **Endpoint ID Required:** BPF programs must have `EFFECTIVE_EP_ID` defined (set via `LXC_ID` in endpoint programs)

2. **No Hot Updates:** Changing `MAX_SHARED_REFS` or `MAX_PRIVATE_OVERRIDES` requires agent restart and endpoint regeneration

3. **Arena Not Resizable:** Arena size fixed at creation; must recreate to resize

4. **Hash Collisions:** Rule hash collisions handled but add overhead; extremely unlikely with 64-bit hash

5. **Kernel Version:** Requires kernel 6.9+ for BPF arena support (specifically `BPF_MAP_TYPE_ARENA`)

---

## Upgrade Path: Legacy → Arena

When enabling arena mode on an existing cluster, the following process must occur:

```
┌─────────────────────────────────────────────────────────────────────────┐
│              UPGRADE PATH: LEGACY → ARENA                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  PHASE 1: PREPARATION(Agent restart with enable-policy-shared-map-arena)│
│  ───────────────────────────────────────────────────────────────────────│
│                                                                         │
│  1. Agent starts with enable-policy-shared-map-arena=true               │
│  2. InitUniversalMaps() creates arena infrastructure:                   │
│     - cilium_policy_a (arena map)                                       │
│     - cilium_policy_s (shared LPM trie)                                 │
│     - cilium_policy_o (overlay map)                                     │
│     - cilium_arena_c (config map)                                       │
│     - cilium_arena_p (pointer map)                                      │
│  3. Legacy per-endpoint maps still exist and are active                 │
│                                                                         │
│  PHASE 2: MIGRATION (Rolling Regeneration)                              │
│  ───────────────────────────────────────────────────────────────────────│
│                                                                         │
│  For each endpoint during regeneration:                                 │
│  1. SyncEndpointOverlay() writes to shared maps                         │
│  2. BPF program is recompiled with ENABLE_BPF_ARENA flag                │
│  3. New BPF program uses policy_lookup_shared()                         │
│  4. Legacy per-endpoint map is NO LONGER WRITTEN TO                     │
│     (NewPolicyMap skips per-endpoint map creation when SharedMapOnly)   │
│                                                                         │
│  During this phase (rolling regeneration):                              │
│  - Old endpoints: Use legacy per-endpoint maps                          │
│  - New endpoints: Use shared arena + overlay                            │
│                                                                         │
│  PHASE 3: CLEANUP (After all endpoints regenerated)                     │
│  ───────────────────────────────────────────────────────────────────────│
│                                                                         │
│  1. Legacy per-endpoint maps can be deleted                             │
│  2. Memory reclaimed from unused per-endpoint maps                      │
│  3. Only shared arena infrastructure remains                            │
│                                                                         │
│  NOTE: Currently, cleanup is MANUAL. Legacy maps remain until           │
│  explicit deletion or node restart.                                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Upgrade Verification

```bash
# Check arena maps exist
bpftool map list | grep cilium_policy

# Expected output after upgrade:
# cilium_policy_a  arena
# cilium_policy_s  lpm_trie
# cilium_policy_o  hash

# Verify endpoints are using shared maps
cilium endpoint list -o json | jq '.[].status.policy'

# Check overlay entries
bpftool map dump name cilium_policy_o
```

---

## Rollback Path: Arena → Legacy

If arena mode causes issues, there are two rollback approaches:

```
┌─────────────────────────────────────────────────────────────────────────┐
│              ROLLBACK PATH: ARENA → LEGACY                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  APPROACH 1: GRACEFUL ROLLBACK (Recommended)                            │
│  ───────────────────────────────────────────────────────────────────────│
│                                                                         │
│  1. Update ConfigMap: enable-policy-shared-map-arena=false              │
│  2. Rolling restart of cilium agents                                    │
│  3. During restart:                                                     │
│     - Agent detects arena disabled                                      │
│     - Endpoint regeneration creates per-endpoint maps                   │
│     - BPF programs compiled WITHOUT ENABLE_BPF_ARENA                    │
│     - policy_can_access() uses per-endpoint map lookup                  │
│  4. Arena maps remain pinned but unused                                 │
│  5. Eventual cleanup: Delete arena maps from /sys/fs/bpf/               │
│                                                                         │
│  Timeline: Rolling update, no connectivity gap                          │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  APPROACH 2: HARD ROLLBACK (Emergency)                                  │
│  ───────────────────────────────────────────────────────────────────────│
│                                                                         │
│  1. kubectl rollout restart daemonset/cilium -n kube-system             │
│     (with enable-policy-shared-map-arena=false)                         │
│  2. Delete arena maps:                                                  │
│     rm /sys/fs/bpf/tc/globals/cilium_policy_a                           │
│     rm /sys/fs/bpf/tc/globals/cilium_policy_s                           │
│     rm /sys/fs/bpf/tc/globals/cilium_policy_o                           │
│     rm /sys/fs/bpf/tc/globals/cilium_arena_*                            │
│  3. Restart cilium agents to recreate per-endpoint maps                 │
│                                                                         │
│  Risk: Brief connectivity disruption during restart                     │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  WHAT'S NOT SUPPORTED (Currently):                                      │
│  ───────────────────────────────────────────────────────────────────────│
│                                                                         │
│  - Hot-swap between arena and legacy without restart                    │
│  - Automatic migration of in-flight connections during rollback         │
│  - Arena map resizing without recreating                                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Rollback Verification

```bash
# Verify arena mode is disabled
cilium config | grep enable-policy-shared-map-arena
# Expected: enable-policy-shared-map-arena: false

# Verify per-endpoint maps exist
ls /sys/fs/bpf/tc/globals/cilium_policy_*
# Should see cilium_policy_00XXX for each endpoint

# Verify arena maps are gone (or unused)
bpftool map list | grep -E "cilium_policy_[aso]"
# Should be empty after cleanup
```

---

## Arena Memory Fragmentation

### The Problem

Arena memory uses a simple linear allocator:

```
┌─────────────────────────────────────────────────────────────────────────┐
│              ARENA FRAGMENTATION PROBLEM                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Linear Allocation (Current Implementation):                            │
│  ───────────────────────────────────────────                            │
│                                                                         │
│  Arena Memory Layout:                                                   │
│  ┌────┬────┬────┬────┬────┬────┬────┬────┬────┬────┬────┐               │
│  │ R1 │ R2 │ R3 │ R4 │ R5 │ R6 │ R7 │ R8 │FREE│FREE│... │               │
│  └────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┘               │
│                                     ▲                                   │
│                                     │                                   │
│                              nextArenaOff                               │
│                                                                         │
│  After deleting R2, R4, R6 (policies removed):                          │
│  ┌────┬────┬────┬────┬────┬────┬────┬────┬────┬────┬────┐               │
│  │ R1 │XXXX│ R3 │XXXX│ R5 │XXXX│ R7 │ R8 │FREE│FREE│... │               │
│  └────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┘               │
│       ▲         ▲         ▲                                             │
│       │         │         │                                             │
│       └─────────┴─────────┴── FRAGMENTED (not reclaimed)                │
│                                                                         │
│  CRITICAL LIMITATION: Deleted rules leave holes that are NEVER reclaimed│
│  - nextArenaOff only moves forward                                      │
│  - Memory "leaks" over time with policy churn                           │
│  - Eventually arena fills up even with few active rules                 │
│  - ONLY an agent restart resets the allocator and arena memory          │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  Impact Analysis:                                                       │
│  ────────────────                                                       │
│  - Rule size: ~64 bytes                                                 │
│  - Arena default: 16MB (4096 pages × 4KB)                               │
│  - Max rules before fragmentation matters: ~250,000                     │
│                                                                         │
│  Scenarios where fragmentation is problematic:                          │
│  1. High policy churn (frequent add/remove of policies)                 │
│  2. Long-running clusters without agent restarts                        │
│  3. CI/CD environments with frequent deployments                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Current Mitigation

```
┌─────────────────────────────────────────────────────────────────────────┐
│              FRAGMENTATION MITIGATION (Current)                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. RULE DEDUPLICATION                                                  │
│  ─────────────────────                                                  │
│  - Same rule (hash) is stored ONCE, shared via refcount                 │
│  - Reduces total allocations significantly                              │
│  - Rule only deleted when refcount reaches 0                            │
│                                                                         │
│  2. LARGE ARENA SIZE                                                    │
│  ────────────────────                                                   │
│  - Default 16MB can hold ~250K rules                                    │
│  - Typical cluster: 10K endpoints × 50 rules = 500K rule refs           │
│  - With 90% dedup: ~50K unique rules = 3.2MB                            │
│  - Headroom for fragmentation: 12.8MB                                   │
│                                                                         │
│  3. AGENT RESTART RESETS ARENA                                          │
│  ──────────────────────────────                                         │
│  - On agent restart: Arena can be recreated fresh                       │
│  - All rules repopulated from scratch                                   │
│  - Fragmentation eliminated                                             │
│  - Scheduled restarts (maintenance windows) mitigate long-term frag     │
│                                                                         │
│  4. RULE SET ID STABILITY                                               │
│  ────────────────────────                                               │
│  - Hash-based rule_set_id: Same rules → same ID                         │
│  - Policy update with same rules reuses existing allocation             │
│  - Reduces churn from "modify port then change back" scenarios          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Future Solutions (Not Implemented)

```
┌─────────────────────────────────────────────────────────────────────────┐
│              FUTURE FRAGMENTATION SOLUTIONS                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  OPTION 1: FREE LIST                                                    │
│  ───────────────────                                                    │
│  - Track freed slots in a linked list                                   │
│  - New allocations check free list first                                │
│  - Complexity: Medium                                                   │
│  - Benefit: Reclaims fragmented space                                   │
│                                                                         │
│  Implementation sketch:                                                 │
│  type ArenaAllocator struct {                                           │
│      freeList []uint32  // Offsets of freed slots                       │
│  }                                                                      │
│  func (a *ArenaAllocator) Allocate() uint32 {                           │
│      if len(a.freeList) > 0 {                                           │
│          offset := a.freeList[len(a.freeList)-1]                        │
│          a.freeList = a.freeList[:len(a.freeList)-1]                    │
│          return offset                                                  │
│      }                                                                  │
│      offset := a.nextArenaOff                                           │
│      a.nextArenaOff += ruleSize                                         │
│      return offset                                                      │
│  }                                                                      │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  OPTION 2: COMPACTION                                                   │
│  ───────────────────                                                    │
│  - Periodically compact arena memory                                    │
│  - Move all active rules to beginning                                   │
│  - Update all LPM entries with new offsets                              │
│  - Complexity: High (requires coordinated update)                       │
│  - Benefit: Full reclamation, optimal packing                           │
│                                                                         │
│  Challenges:                                                            │
│  - BPF programs reading during compaction                               │
│  - Need atomic offset updates or brief pause                            │
│  - Must update all LPM trie entries                                     │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  OPTION 3: GENERATIONAL ARENAS                                          │
│  ─────────────────────────────                                          │
│  - Multiple arena regions (generations)                                 │
│  - New allocations go to current generation                             │
│  - Old generations marked read-only, eventually freed                   │
│  - Complexity: High                                                     │
│  - Benefit: No fragmentation within generation                          │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  OPTION 4: FIXED-SIZE SLAB ALLOCATOR                                    │
│  ────────────────────────────────────                                   │
│  - All rules are same size (64 bytes)                                   │
│  - Arena divided into fixed-size slots                                  │
│  - Bitmap tracks free/used slots                                        │
│  - Complexity: Low                                                      │
│  - Benefit: Simple, no external fragmentation                           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Impacts / Key Questions

### Impact: Massive Memory Reduction
The primary impact of this proposal is a **90-99% reduction in kernel memory usage** for network policies in large-scale clusters. By moving from O(Rules × Endpoints) to O(Unique Rules), we eliminate the memory bottleneck that currently limits scale. This allows higher pod density and more complex policies without risking node instability.

### Impact: Complexity Shift
Complexity shifts from the control plane (managing thousands of individual maps) to the dataplane allocator (managing shared arena memory and reference counts). While this simplifies the map management logic, it introduces new complexity in:
-   **Arena Allocator:** Handling fragmentation and shared memory safely.
-   **Reference Counting:** Ensuring rules are only deleted when no longer referenced.
-   **Verifier Limits:** Ensuring the shared lookup logic remains within BPF complexity limits, which is actually *improved* by avoiding loops.

### Key Question: Failure Modes & Recovery
**Q: What happens if the arena memory is exhausted or fragmented?**
A: New policy additions will fail, but existing connectivity remains intact. The current mitigation is a large arena size (default 16MB) which accommodates ~250k rules. If fragmentation becomes severe, an agent restart is required to defragment the arena. Future work will implement better allocators (free lists, compaction).

### Key Question: Kernel Dependency
**Q: How do we handle clusters with mixed kernel versions?**
A: The feature requires Linux 6.9+ for `BPF_MAP_TYPE_ARENA`. The agent automatically detects kernel support and falls back to legacy per-endpoint maps on older capabilities. This allows for safe, gradual rollouts and mixed-node clusters.

---

## Other Considerations

### Version Compatibility

```
┌─────────────────────────────────────────────────────────────────────────┐
│              VERSION COMPATIBILITY                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Kernel Requirements:                                                   │
│  ─────────────────────                                                  │
│  - BPF_MAP_TYPE_ARENA: Linux 6.9+ (bpf: Add BPF_MAP_TYPE_ARENA)         │
│  - BPF arena kfuncs: Linux 6.9+                                         │
│  - Recommended: Linux 6.9+ for stability                                │
│                                                                         │
│  Detection at Runtime:                                                  │
│  ─────────────────────                                                  │
│  // pkg/maps/policymap/universal_maps.go                                │
│  // Attempt to create arena map - if kernel doesn't support,            │
│  // creation fails and we fall back to legacy                           │
│                                                                         │
│  Cilium Version:                                                        │
│  ────────────────                                                       │
│  - Arena support: Cilium 1.16+ (PoC/experimental)                       │
│  - Production ready: TBD                                                │
│                                                                         │
│  Mixed Cluster Compatibility:                                           │
│  ────────────────────────────                                           │
│  - Old agents (arena disabled): Use per-endpoint maps                   │
│  - New agents (arena enabled): Use shared maps                          │
│  - No cross-node dependencies (maps are node-local)                     │
│  - Safe to rolling upgrade                                              │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  HOW TO ADDRESS / MAKE IT SAFE:                                         │
│  ───────────────────────────────                                        │
│                                                                         │
│  1. AUTOMATIC KERNEL DETECTION (Recommended Implementation)             │
│     ─────────────────────────────────────────────────────────           │
│     func probeArenaSupport() bool {                                     │
│         // Create a tiny test arena map                                 │
│         spec := &ebpf.MapSpec{                                          │
│             Type:       ebpf.Arena,                                     │
│             MaxEntries: 1,                                              │
│         }                                                               │
│         m, err := ebpf.NewMap(spec)                                     │
│         if err != nil {                                                 │
│             return false // Kernel doesn't support arena                │
│         }                                                               │
│         m.Close()                                                       │
│         return true                                                     │
│     }                                                                   │
│                                                                         │
│     // In agent startup:                                                │
│     if option.Config.EnableArena && !probeArenaSupport() {              │
│         log.Warn("Arena not supported, falling back to legacy")         │
│         option.Config.EnableArena = false                               │
│     }                                                                   │
│                                                                         │
│  2. FEATURE GATE WITH GRACEFUL FALLBACK                                 │
│     ─────────────────────────────────────                               │
│     - Arena mode is OPT-IN (enable-policy-shared-map-arena=false)       │
│     - If enabled but kernel lacks support → automatic fallback          │
│     - No crash, no data loss, just reduced memory efficiency            │
│                                                                         │
│  3. MINIMUM KERNEL VERSION CHECK                                        │
│     ──────────────────────────────                                      │
│     Add to agent startup validation:                                    │
│     - Parse /proc/version or use uname()                                │
│     - Warn if kernel < 6.9 and arena is requested                       │
│     - Consider blocking arena on known-buggy kernel versions            │
│                                                                         │
│  WHY IT'S SAFE:                                                         │
│  ───────────────                                                        │
│  - Maps are NODE-LOCAL: No cross-node coordination needed               │
│  - Rolling upgrade is safe: Old/new agents don't share maps             │
│  - Fallback is automatic: Policy enforcement continues with legacy      │
│  - No data plane disruption: Existing connections unaffected            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Metrics and Observability

```
┌─────────────────────────────────────────────────────────────────────────┐
│              METRICS TO ADD (Future)                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Arena Health Metrics:                                                  │
│  ─────────────────────                                                  │
│  cilium_bpf_arena_bytes_allocated    # Total bytes allocated            │
│  cilium_bpf_arena_bytes_used         # Bytes with active refs           │
│  cilium_bpf_arena_fragmentation_pct  # (allocated-used)/allocated       │
│  cilium_bpf_arena_rules_total        # Total unique rules in arena      │
│  cilium_bpf_arena_rules_shared_pct   # Rules with refcount > 1          │
│                                                                         │
│  Rule Set Metrics:                                                      │
│  ─────────────────                                                      │
│  cilium_policy_rule_sets_total       # Number of unique rule sets       │
│  cilium_policy_rule_sets_refcount    # Histogram of refcounts           │
│  cilium_policy_rule_sets_size        # Histogram of rules per set       │
│                                                                         │
│  Overlay Metrics:                                                       │
│  ────────────────                                                       │
│  cilium_policy_overlay_entries       # Total overlay entries            │
│  cilium_policy_overlay_shared_refs   # Histogram of shared ref counts   │
│  cilium_policy_overlay_spillover     # Entries using private overrides  │
│                                                                         │
│  Operational Metrics:                                                   │
│  ────────────────────                                                   │
│  cilium_policy_arena_sync_duration   # Time to sync endpoint overlay    │
│  cilium_policy_arena_sync_errors     # Failed sync operations           │
│  cilium_policy_arena_lpm_entries     # Entries in shared LPM trie       │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  HOW TO IMPLEMENT:                                                      │
│  ─────────────────                                                      │
│                                                                         │
│  1. ADD METRICS TO SHARED MANAGER (pkg/maps/policymap/sharedmanager.go) │
│     ─────────────────────────────────────────────────────────────────── │
│     var (                                                               │
│         metricArenaAllocated = promauto.NewGauge(prometheus.GaugeOpts{  │
│             Namespace: "cilium",                                        │
│             Subsystem: "bpf_arena",                                     │
│             Name:      "bytes_allocated",                               │
│             Help:      "Total bytes allocated in arena memory",         │
│         })                                                              │
│         metricArenaFragmentation=promauto.NewGauge(prometheus.GaugeOpts{│
│             Namespace: "cilium",                                        │
│             Subsystem: "bpf_arena",                                     │
│             Name:      "fragmentation_ratio",                           │
│             Help:      "Ratio of wasted bytes to allocated bytes",      │
│         })                                                              │
│         metricSyncDuration = promauto.NewHistogram(prometheus.HistogramOpts{│
│             Namespace: "cilium",                                        │
│             Subsystem: "policy_arena",                                  │
│             Name:      "sync_duration_seconds",                         │
│             Help:      "Time to sync endpoint overlay",                 │
│             Buckets:   prometheus.DefBuckets,                           │
│         })                                                              │
│     )                                                                   │
│                                                                         │
│  2. UPDATE METRICS IN SYNC OPERATIONS                                   │
│     ─────────────────────────────────                                   │
│     func SyncEndpointOverlay(...) {                                     │
│         start := time.Now()                                             │
│         defer func() {                                                  │
│             metricSyncDuration.Observe(time.Since(start).Seconds())     │
│         }()                                                             │
│         // ... existing logic                                           │
│         metricArenaAllocated.Set(float64(mgr.allocator.nextArenaOff))   │
│     }                                                                   │
│                                                                         │
│  3. EXPOSE VIA /metrics ENDPOINT                                        │
│     ──────────────────────────                                          │
│     - Metrics auto-registered via promauto                              │
│     - Available at cilium-agent:9962/metrics                            │
│     - Grafana dashboard: Add arena panel to policy dashboard            │
│                                                                         │
│  WHY THIS IS IMPORTANT:                                                 │
│  ───────────────────────                                                │
│  - Detect fragmentation BEFORE arena exhaustion                         │
│  - Alert on high sync error rates                                       │
│  - Capacity planning: Know when to increase arena size                  │
│  - Debug performance issues: Identify slow syncs                        │
│                                                                         │
│  ALERTING RULES (Prometheus):                                           │
│  ─────────────────────────────                                          │
│  - alert: ArenaFragmentationHigh                                        │
│    expr: cilium_bpf_arena_fragmentation_ratio > 0.5                     │
│    for: 1h                                                              │
│    labels: {severity: warning}                                          │
│    annotations: {summary: "Consider agent restart to defragment"}       │
│                                                                         │
│  - alert: ArenaNearCapacity                                             │
│    expr: cilium_bpf_arena_bytes_allocated / cilium_bpf_arena_max > 0.8  │
│    for: 5m                                                              │
│    labels: {severity: critical}                                         │
│    annotations: {summary: "Arena approaching capacity limit"}           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Failure Modes

```
┌─────────────────────────────────────────────────────────────────────────┐
│              FAILURE MODES AND RECOVERY                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. ARENA MAP CREATION FAILS                                            │
│  ───────────────────────────                                            │
│  Cause: Kernel too old, insufficient memory, bpffs not mounted          │
│  Detection: Error from InitUniversalMaps()                              │
│  Recovery: Fall back to legacy per-endpoint maps                        │
│  Impact: No memory savings, but full functionality                      │
│                                                                         │
│  HOW TO HANDLE:                                                         │
│  - Already implemented: InitUniversalMaps() returns error               │
│  - Agent continues with legacy mode automatically                       │
│  - Add metric: cilium_bpf_arena_fallback_total                          │
│  - Log: "Arena creation failed, using legacy maps: %v"                  │
│  WHY IT'S SAFE: Legacy mode is battle-tested, no functionality loss     │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  2. ARENA MMAP FAILS                                                    │
│  ────────────────────                                                   │
│  Cause: Address conflict, insufficient virtual memory                   │
│  Detection: ENOMEM or EEXIST from mmap syscall                          │
│  Recovery: Agent fails to start, requires investigation                 │
│  Impact: Agent restart loop until resolved                              │
│                                                                         │
│  HOW TO HANDLE:                                                         │
│  - Try alternative addresses if MAP_FIXED fails:                        │
│    addresses := []uintptr{0x10000000000, 0x20000000000, 0x30000000000}  │
│    for _, addr := range addresses {                                     │
│        if mmap(addr, ...) == nil { break }                              │
│    }                                                                    │
│  - If all fail: Fall back to legacy mode instead of crash               │
│  - Add: --arena-base-address flag for manual override                   │
│  WHY IT'S SAFE: With fallback, agent always starts successfully         │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  3. OVERLAY MAP FULL                                                    │
│  ────────────────────                                                   │
│  Cause: More endpoints than POLICY_MAP_SIZE                             │
│  Detection: Error from overlay map Update()                             │
│  Recovery: Increase bpf-policy-map-max, restart agent                   │
│  Impact: New endpoints cannot be created                                │
│                                                                         │
│  HOW TO HANDLE:                                                         │
│  - Pre-check before creating endpoint:                                  │
│    if overlayMap.Len() >= maxEntries - 100 {                            │
│        log.Warn("Overlay map near capacity")                            │
│        metric.Inc()                                                     │
│    }                                                                    │
│  - Implement LRU eviction for stale entries (future)                    │
│  - Dynamic resizing: Create new larger map, migrate entries             │
│  WHY IT'S SAFE: Existing endpoints unaffected, only new creation fails  │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  4. SHARED LPM TRIE FULL                                                │
│  ────────────────────────                                               │
│  Cause: More unique rules than SharedLPMMaxEntries                      │
│  Detection: Error from LPM map Update()                                 │
│  Recovery: Increase SharedLPMMaxEntries, restart agent                  │
│  Impact: New rules cannot be added                                      │
│                                                                         │
│  HOW TO HANDLE:                                                         │
│  - Check capacity before adding:                                        │
│    if lpmMap.Len() >= SharedLPMMaxEntries * 0.9 {                       │
│        log.Error("LPM trie at 90% capacity")                            │
│    }                                                                    │
│  - Consider: Per-endpoint fallback to legacy map when full              │
│  - Expose metric: cilium_bpf_lpm_trie_capacity_ratio                    │
│  WHY IT'S SAFE: Existing policies keep working, only new additions fail │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  5. ARENA MEMORY EXHAUSTED                                              │
│  ──────────────────────────                                             │
│  Cause: Fragmentation + high rule count                                 │
│  Detection: nextArenaOff exceeds arena size                             │
│  Recovery: Agent restart to reset arena                                 │
│  Impact: New rules fail until restart                                   │
│                                                                         │
│  HOW TO HANDLE:                                                         │
│  - Track high-water mark: metricArenaHighWaterMark.Set(nextArenaOff)    │
│  - Implement free list allocator (see Fragmentation section)            │
│  - Automated recovery:                                                  │
│    if arenaUsage > 0.95 {                                               │
│        log.Error("Arena exhausted, triggering graceful restart")        │
│        // Signal to orchestrator for rolling restart                    │
│    }                                                                    │
│  - Proactive: Schedule periodic agent restarts in maintenance window    │
│  WHY IT'S SAFE: Restart is graceful, connections preserved via BPF      │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  6. REFCOUNT LEAK                                                       │
│  ─────────────────                                                      │
│  Cause: Bug in SyncEndpointOverlay or RemoveEndpointOverlay             │
│  Detection: Rules never deleted despite 0 endpoints                     │
│  Recovery: Agent restart resets all state                               │
│  Impact: Memory leak over time                                          │
│                                                                         │
│  HOW TO HANDLE:                                                         │
│  - Add consistency check in periodic GC:                                │
│    func (a *RuleSetAllocator) ConsistencyCheck() {                      │
│        for id, refcount := range a.refcount {                           │
│            if refcount > 0 && !a.hasEndpointRefs(id) {                  │
│                log.Warn("Orphaned rule set", "id", id, "refcount", rc)  │
│                // Option: Auto-cleanup orphans                          │
│            }                                                            │
│        }                                                                │
│    }                                                                    │
│  - Run consistency check every 5 minutes                                │
│  - Expose: cilium_bpf_arena_orphaned_rules gauge                        │
│  WHY IT'S SAFE: Detection allows proactive restart before exhaustion    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Security Considerations

```
┌─────────────────────────────────────────────────────────────────────────┐
│              SECURITY CONSIDERATIONS                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. SHARED MEMORY ACCESS                                                │
│  ────────────────────────                                               │
│  Risk: Arena memory is shared between BPF and userspace                 │
│  Concern: Could a compromised process tamper with policies?             │
│                                                                         │
│  WHY IT'S SAFE:                                                         │
│  - Only cilium-agent process has mmap access (requires CAP_BPF)         │
│  - Agent runs as root in host PID namespace                             │
│  - Container processes CANNOT access /sys/fs/bpf (not mounted)          │
│  - BPF verifier ensures programs can only read arena, not write         │
│                                                                         │
│  HARDENING:                                                             │
│  - Ensure /sys/fs/bpf mounted with restrictive permissions (0700)       │
│  - Consider SELinux/AppArmor policy for cilium-agent                    │
│  - Audit: Log any unexpected arena access attempts                      │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  2. POLICY ISOLATION                                                    │
│  ────────────────────                                                   │
│  Risk: Could endpoint A read endpoint B's policies?                     │
│  Concern: Information leakage between tenants                           │
│                                                                         │
│  WHY IT'S SAFE:                                                         │
│  - BPF program ONLY queries with its own rule_set_id                    │
│  - rule_set_id is derived from EFFECTIVE_EP_ID (compiled into BPF)      │
│  - Endpoint cannot spoof another endpoint's ID                          │
│  - LPM trie key includes rule_set_id: different IDs = different results │
│                                                                         │
│  CODE PROOF:                                                            │
│  // bpf/lib/policy.h                                                    │
│  __u32 ep_id = EFFECTIVE_EP_ID;  // Compile-time constant               │
│  overlay = map_lookup(&cilium_policy_o, &ep_id);                        │
│  // Endpoint cannot change EFFECTIVE_EP_ID at runtime                   │
│                                                                         │
│  HARDENING:                                                             │
│  - Verify EFFECTIVE_EP_ID is set correctly during BPF compilation       │
│  - Add BPF static assertion: rule_set_id must match overlay lookup      │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  3. DENIAL OF SERVICE                                                   │
│  ─────────────────────                                                  │
│  Risk: Malicious policies could exhaust arena memory                    │
│  Concern: One tenant affects all tenants on the node                    │
│                                                                         │
│  WHY IT'S SAFE (with mitigations):                                      │
│  - Same risk exists in legacy architecture (map entry limits)           │
│  - Deduplication reduces impact: 1000 identical policies = 1 rule set   │
│  - Large arena (16MB default) provides headroom                         │
│                                                                         │
│  HARDENING:                                                             │
│  - Implement per-namespace policy quotas:                               │
│    maxPoliciesPerNamespace: 100                                         │
│    maxRulesPerPolicy: 1000                                              │
│  - Rate limit policy creation:                                          │
│    policyCreationRateLimit: 10/s                                        │
│  - Alert when arena usage > 80%                                         │
│  - ResourceQuota integration for CiliumNetworkPolicy objects            │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  4. INTEGRITY                                                           │
│  ───────────────                                                        │
│  Risk: Could arena content be corrupted?                                │
│  Concern: Corrupted policies = security bypass                          │
│                                                                         │
│  WHY IT'S SAFE:                                                         │
│  - Arena content written ONLY by cilium-agent (single writer)           │
│  - BPF programs are READ-ONLY (no bpf_probe_write_user for arena)       │
│  - Pinned maps protected by bpffs permissions                           │
│  - Kernel ensures MAP_SHARED coherence                                  │
│                                                                         │
│  HARDENING:                                                             │
│  - Implement write checksums for arena entries:                         │
│    type ArenaPolicyEntry struct {                                       │
│        ...                                                              │
│        Checksum uint32  // CRC32 of entry fields                        │
│    }                                                                    │
│  - BPF validates checksum before applying policy (optional, perf cost)  │
│  - Periodic integrity scan in agent background goroutine                │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  5. PRIVILEGE ESCALATION                                                │
│  ───────────────────────                                                │
│  Risk: Could arena manipulation grant unauthorized access?              │
│  Concern: Write ALLOW rule for attacker-controlled identity             │
│                                                                         │
│  WHY IT'S SAFE:                                                         │
│  - Only cilium-agent can write to arena (CAP_BPF + CAP_SYS_ADMIN)       │
│  - Agent validates policies via Kubernetes RBAC before writing          │
│  - Kubernetes API server enforces CiliumNetworkPolicy admission         │
│                                                                         │
│  HARDENING:                                                             │
│  - Enable ValidatingAdmissionWebhook for CNP                            │
│  - Audit log all policy changes via Kubernetes audit                    │
│  - Use OPA/Gatekeeper for additional policy validation                  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Testing Gaps (Known)

```
┌─────────────────────────────────────────────────────────────────────────┐
│              TESTING GAPS TO ADDRESS                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Unit Tests (pkg/maps/policymap/*_test.go):                             │
│  ✓ TestScenario_AddPolicy                                               │
│  ✓ TestScenario_AddAnotherPolicy                                        │
│  ✓ TestScenario_RemovePolicy                                            │
│  ✓ TestScenario_RemoveEndpoint                                          │
│  ✓ TestScenario_UpdatePolicy                                            │
│  ✓ TestScenario_SharedPolicyDeduplication                               │
│  ✓ TestScenario_DifferentPolicies                                       │
│  ✓ TestScenario_RemoveOneOfShared                                       │
│  ✓ TestScenario_EmptyPolicy                                             │
│  ✓ TestScenario_ManyPorts                                               │
│  ✓ TestScenario_RapidUpdates                                            │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  MISSING TESTS WITH IMPLEMENTATION PLANS:                               │
│  ─────────────────────────────────────────                              │
│                                                                         │
│  ✗ Deny rule precedence over allow rules                                │
│    ─────────────────────────────────────                                │
│    HOW TO TEST:                                                         │
│    func TestScenario_DenyPrecedence(t *testing.T) {                     │
│        // Create allow rule for port 80                                 │
│        allowRule := makeAllowRule(80)                                   │
│        // Create deny rule for port 80 (should override)                │
│        denyRule := makeDenyRule(80)                                     │
│        SyncEndpointOverlay(701, combineRules(allowRule, denyRule))      │
│        // Verify LPM lookup returns DENY (longer prefix wins)           │
│        result := lookupPolicy(ruleSetID, 80)                            │
│        require.True(t, result.IsDeny())                                 │
│    }                                                                    │
│    WHY SAFE WITHOUT IT: LPM naturally handles - deny has full prefix    │
│                                                                         │
│  ✗ L7/proxy rule handling                                               │
│    ─────────────────────────                                            │
│    HOW TO TEST:                                                         │
│    func TestScenario_ProxyRedirect(t *testing.T) {                      │
│        rule := policyTypes.Key{...}                                     │
│        entry := policyTypes.MapStateEntry{ProxyPort: 9080}              │
│        SyncEndpointOverlay(701, singleRule(rule, entry))                │
│        // Verify arena entry has correct proxy_port                     │
│        arenaEntry := readArenaEntry(offset)                             │
│        require.Equal(t, uint16(9080), arenaEntry.ProxyPort)             │
│    }                                                                    │
│    WHY SAFE WITHOUT IT: ProxyPort passed through unchanged to arena     │
│                                                                         │
│  ✗ Agent restart + state restoration                                    │
│    ────────────────────────────────                                     │
│    HOW TO TEST:                                                         │
│    func TestScenario_AgentRestart(t *testing.T) {                       │
│        // Setup: Create policies                                        │
│        SyncEndpointOverlay(701, makeRuleSeq(80, 443))                   │
│        // Simulate restart: Reset in-memory state                       │
│        sharedMgr = nil; sharedMgrOnce = sync.Once{}                     │
│        // Restore from pinned maps                                      │
│        RestoreEndpointOverlay(701)                                      │
│        // Verify refcounts are correct                                  │
│        mgr := getSharedManager()                                        │
│        require.Equal(t, 1, mgr.allocator.refcount[ruleSetID])           │
│    }                                                                    │
│    WHY SAFE WITHOUT IT: Current impl doesn't persist refcounts;         │
│    restart rebuilds from scratch which is correct but slower            │
│                                                                         │
│  ✗ Arena exhaustion handling                                            │
│    ────────────────────────────                                         │
│    HOW TO TEST:                                                         │
│    func TestScenario_ArenaExhaustion(t *testing.T) {                    │
│        // Use small arena (1 page = 4KB ≈ 64 rules)                     │
│        setupSmallArena(t, 1)                                            │
│        // Try to add more rules than fit                                │
│        for i := 0; i < 100; i++ {                                       │
│            err := SyncEndpointOverlay(uint16(i), makeRuleSeq(uint16(i)))│
│        }                                                                │
│        // Verify graceful failure                                       │
│        require.ErrorContains(t, err, "arena exhausted")                 │
│    }                                                                    │
│    WHY SAFE WITHOUT IT: 16MB arena >> typical usage; failure is loud    │
│                                                                         │
│  ✗ Concurrent endpoint updates                                          │
│    ────────────────────────────                                         │
│    HOW TO TEST:                                                         │
│    func TestScenario_ConcurrentUpdates(t *testing.T) {                  │
│        var wg sync.WaitGroup                                            │
│        for i := 0; i < 100; i++ {                                       │
│            wg.Add(1)                                                    │
│            go func(epID uint16) {                                       │
│                defer wg.Done()                                          │
│                SyncEndpointOverlay(epID, makeRuleSeq(80))               │
│            }(uint16(700 + i))                                           │
│        }                                                                │
│        wg.Wait()                                                        │
│        // Verify all endpoints have correct overlay                     │
│    }                                                                    │
│    WHY SAFE WITHOUT IT: sharedManager has mutex; concurrent-safe        │
│                                                                         │
│  ✗ LPM prefix boundary conditions (0/8/16/24 bits)                      │
│    ─────────────────────────────────────────────                        │
│    HOW TO TEST:                                                         │
│    func TestScenario_LPMPrefixBoundaries(t *testing.T) {                │
│        cases := []struct {                                              │
│            proto, port uint16                                           │
│            expectedPrefix uint8                                         │
│        }{                                                               │
│            {0, 0, 0},      // L3-only: any proto, any port              │
│            {6, 0, 8},      // TCP, any port                             │
│            {6, 80, 24},    // TCP, specific port                        │
│            {6, 0x8000, 9}, // TCP, port range (MSB only)                │
│        }                                                                │
│        for _, tc := range cases {                                       │
│            // Verify prefix calculation                                 │
│        }                                                                │
│    }                                                                    │
│    WHY SAFE WITHOUT IT: Already fixed in rule_set_allocator.go:131-142  │
│                                                                         │
│  ✗ Hash collision handling                                              │
│    ──────────────────────────                                           │
│    HOW TO TEST:                                                         │
│    func TestScenario_HashCollision(t *testing.T) {                      │
│        // Force collision by mocking hash function                      │
│        oldHash := computeRuleSetHash                                    │
│        computeRuleSetHash = func(...) ruleSetKey { return "fixed" }     │
│        defer func() { computeRuleSetHash = oldHash }()                  │
│        // Add two different rule sets                                   │
│        SyncEndpointOverlay(701, makeRuleSeq(80))                        │
│        SyncEndpointOverlay(702, makeRuleSeq(443))                       │
│        // Verify they get different rule_set_ids (collision resolved)   │
│    }                                                                    │
│    WHY SAFE WITHOUT IT: SHA256 collision is astronomically unlikely     │
│                                                                         │
│  ✗ Mixed legacy + arena during rolling upgrade                          │
│    ──────────────────────────────────────────                           │
│    HOW TO TEST:                                                         │
│    func TestScenario_MixedMode(t *testing.T) {                          │
│        // Endpoint 701: legacy mode (arena disabled)                    │
│        option.Config.EnableArena = false                                │
│        createEndpoint(701)                                              │
│        // Endpoint 702: arena mode                                      │
│        option.Config.EnableArena = true                                 │
│        createEndpoint(702)                                              │
│        // Both should work independently                                │
│    }                                                                    │
│    WHY SAFE WITHOUT IT: Legacy/arena are independent code paths         │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  Integration Tests:                                                     │
│  ✓ TestArenaE2E (basic BPF load)                                        │
│                                                                         │
│  ✗ End-to-end policy enforcement with arena                             │
│    HOW TO TEST: Use Cilium connectivity tests with arena enabled        │
│    PRIORITY: HIGH - Critical for production readiness                   │
│                                                                         │
│  ✗ Performance comparison: legacy vs arena                              │
│    HOW TO TEST: benchmark.sh with --compare-legacy flag                 │
│    PRIORITY: MEDIUM - Nice to have for documentation                    │
│                                                                         │
│  ✗ Memory usage validation                                              │
│    HOW TO TEST: Compare /proc/meminfo before/after with 1000 endpoints  │
│    PRIORITY: HIGH - Validates the memory savings claim                  │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  Benchmark (test/arena-benchmark/):                                     │
│  ✓ benchmark.sh - Creates endpoints and measures memory                 │
│                                                                         │
│  ✗ Policy churn benchmark (add/remove cycles)                           │
│    HOW TO TEST:                                                         │
│    for i in {1..1000}; do                                               │
│        kubectl apply -f policy-$i.yaml                                  │
│        kubectl delete -f policy-$i.yaml                                 │
│    done                                                                 │
│    # Measure: arena fragmentation, memory usage, sync latency           │
│    PRIORITY: MEDIUM - Important for long-running clusters               │
│                                                                         │
│  ✗ Fragmentation benchmark (long-running)                               │
│    HOW TO TEST: run policies for 24h, check arena usage                 │
│    PRIORITY: LOW - Can be inferred from churn test                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Future Milestones

### Alpha (Current)
-   Feature gated behind `enable-policy-shared-map-arena=true`.
-   Basic implementation of Arena, Shared LPM Trie, and Overlay Map.
-   Support for Allow/Deny rules and port ranges.
-   Manual verification of memory savings.

### Beta
-   **Fragmentation Handling:** Implement Free List allocator to reuse freed memory slots.
-   **Observability:** Comprehensive metrics for arena usage, fragmentation, and spillover events.
-   **Stability:** Long-running stress tests and churn benchmarks.
-   **Tooling:** Enhanced `cilium bpf policy` CLI for inspecting arena state.

### Stable
-   **Default Enablement:** Enable by default on supported kernels (6.9+).
-   **Dynamic Resizing:** Support for resizing arena (requires restart or advanced remapping).
-   **Compaction:** (Optional) Active memory compaction to eliminate fragmentation without restart.
