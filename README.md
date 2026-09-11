# Casbin Policy Engine — `dev.mcpg.policy.casbin`

> class `policy_engine` · `native` · package `mcpg-plugin-policy-casbin` · artifact `libmcpg_plugin_policy_casbin.so` · BUSL-1.1

An embedded [Casbin](https://casbin.org/) authorization engine. You supply a
model file (`.conf`, defining the request shape, the policy shape and the
matcher) and a policy file (`.csv`); the plugin compiles an enforcer at startup
and answers every authorization question the gateway asks against it. Because
the access-control model lives in the model file rather than in the plugin, the
same artifact expresses ACL, RBAC, RBAC with domains, or ABAC. Reach for it when
your authorization rules are already written for Casbin, or when you want a
small, fully offline engine instead of an external decision service.

## What it does
- Compiles the model and policy files into an enforcer at load, cross-checking
  the model's declared request arity against your translation rules so a
  mismatch fails at startup instead of on the first request.
- Translates the gateway's `(decision_point, input, context)` envelope into a
  Casbin request tuple, one entry per `translation.request_fields` element,
  drawn from caller identity, request context, JSON pointers into the input, or
  literals.
- Maps the enforcement result onto the gateway's policy effects: a matching
  allow rule permits, an explicit deny surfaces the matched policy lines as the
  reason, and a request that matched nothing is either not-applicable (so the
  next engine in the chain gets a turn) or a hard deny.
- Reports a policy version — the SHA-256 over the model and policy files — with
  every decision, so operators can tie an audited decision to the exact bundle.
- Optionally polls both files and swaps the enforcer atomically when they
  change, without dropping in-flight evaluations.
- Coordinates that reload across a cluster when a cluster coordinator is bound,
  so peers converge on the same bundle.
- Treats an enforcer error as a denial rather than an allow.
- Runs entirely in-process. It declares no capabilities and opens no sockets;
  the model and policy come from local files.

## Configuration
Wired in two places. The artifact is loaded from the flat top-level `plugins:`
list, where its `config:` block lives; the gateway then selects it per decision
point from the `governance.policy.engine[]` chain, whose `kind:` accepts either
the short alias `casbin` or the full plugin id.

```yaml
plugins:
  - id: dev.mcpg.policy.casbin
    class: policy_engine
    source: { path: ./plugins/libmcpg_plugin_policy_casbin.so }
    config:
      model_path: /etc/mcpg/casbin/model.conf
      policy_path: /etc/mcpg/casbin/policy.csv
      translation:
        request_fields:
          - { source: identity_subject_id, fallback: anonymous }
          - { source: context, field: tool_name }
          - { source: decision_point }
      evaluation:
        on_default_deny: not_applicable
      reload:
        enabled: true
        check_interval_sec: 60

governance:
  policy:
    engine:
      - kind: casbin
```

To pull the published artifact instead of building it, write
`source: { oci: ghcr.io/mcpg-dev/plugins/policy-casbin }`.
The reference is platform-agnostic; the gateway resolves the variant for its own
OS, architecture and libc.

| Field | Type | Default | Description |
|---|---|---|---|
| `model_path` | string | — (required) | Path to the Casbin model `.conf`. |
| `policy_path` | string | — (required) | Path to the Casbin policy `.csv`. |
| `translation.request_fields` | array | — (required) | One entry per field in the model's `[request_definition]`, in order. |
| `evaluation.on_default_deny` | `not_applicable` \| `deny` | `not_applicable` | What a no-rule-matched result means. |
| `reload.enabled` | bool | `false` | Poll both files and hot-swap the enforcer. |
| `reload.check_interval_sec` | u64 | `60` | Poll cadence when reload is enabled. |

Each `request_fields` entry is tagged by `source`:

| `source` | Extra fields | Resolves to |
|---|---|---|
| `identity_subject_id` | `fallback?` | The caller's subject id. |
| `identity_kind` | `fallback?` | The identity kind. |
| `identity_trust_level` | `fallback?` | The trust level the gateway assigned. |
| `identity_auth_provider` | `fallback?` | The provider that authenticated the caller. |
| `identity_issuer` | `fallback?` | The token issuer. |
| `identity_attribute` | `key`, `fallback?` | One claim from the caller's attribute map. |
| `context` | `field`, `fallback?` | Request context: `tool_name`, `surface`, `transport`, `request_id` or `session_id`. |
| `decision_point` | — | The decision point string itself. |
| `input` | `json_pointer`, `fallback?` | A pointer into the request input; non-string values are stringified, `null` uses the fallback. |
| `literal` | `value` | A constant, for models with a fixed column. |

Unknown fields are rejected, an empty `request_fields` list is rejected, and an
`input` pointer, `literal` value or `identity_attribute` key that is empty is
rejected. A config the plugin cannot honour refuses to register — a policy
engine that starts half-configured is a security hole.

## Operations
The gateway asks at two decision points: `tool.call.pre` before a tool
dispatches, and `plugin.lifecycle.register` when a plugin is about to be
registered. The same translation rules apply at both, which is what
`{ source: decision_point }` is for — it lets one policy file distinguish them.

With the three translation entries above and this model and policy:

```text
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

```text
p, alice, billing.charge, tool.call.pre
```

a `tool.call.pre` request from `alice` for `billing.charge` matches and is
allowed; anything else matches nothing.

Decision mapping:

| Casbin outcome | Effect | Reason |
|---|---|---|
| A policy line matched and allows | `Allow` | — |
| A policy line matched and denies (deny-override models) | `Deny` | The matched policy lines, joined. |
| Nothing matched, `on_default_deny: not_applicable` | `NotApplicable` | — |
| Nothing matched, `on_default_deny: deny` | `Deny` | `casbin: default-deny (no policy matched)` |
| The enforcer itself errored | `Deny` | `casbin enforce error: …` |

Chain composition follows from that mapping: the gateway walks
`governance.policy.engine[]` in order, short-circuiting on the first `Allow` or
`Deny`, while `NotApplicable` falls through to the next engine. Keep the default
`not_applicable` when this engine is one voice among several; switch to `deny`
when it is the sole authority and anything unmatched must be refused.

## Change-watching
With `reload.enabled: true` the plugin polls `model_path` and `policy_path` on
`check_interval_sec` and rebuilds the enforcer when their combined fingerprint
changes. Each evaluation snapshots the current enforcer, so a swap mid-flight
never affects a decision already in progress. With reload off, the enforcer is
built once and picking up an edited policy requires a restart.

When the host provides a cluster coordinator, the plugin publishes its bundle
fingerprint on `policy.casbin.policies-loaded` at startup and subscribes to the
same topic. A peer announcing a different fingerprint triggers an out-of-band
poll on this node, so instances converge instead of drifting apart between
ticks. Coordination is best-effort: a failure to publish or subscribe is logged
and never blocks registration.

## Observability
Every evaluation increments `mcpg_policy_casbin_decisions_total`, labelled by
`decision_point` and `outcome` (`allow`, `deny`, `not_applicable`), and records
`mcpg_policy_casbin_evaluate_ms` labelled by `decision_point`.

When the host installs its observability handle, the plugin also opens a
`policy_casbin.evaluate` span carrying the decision point and the active bundle
fingerprint, and reports `mcpg_policy_casbin_latency_seconds` plus
`mcpg_policy_casbin_decisions_total` labelled by `outcome`. Denials emit a
`dev.mcpg.policy.casbin.deny` audit event carrying the decision point, subject,
resource, matched rules and policy version; enforcer failures emit
`dev.mcpg.policy.casbin.error`. Allow and not-applicable outcomes do not emit
audit events.

## Build
The `cdylib-export` feature is on by default, so a standalone build already
produces a loadable artifact; a binary that links several plugins together turns
it off so they do not all export `mcpg_plugin_register`:

```bash
cargo build -p mcpg-plugin-policy-casbin --features cdylib-export --release   # → target/release/libmcpg_plugin_policy_casbin.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- How the gateway evaluates policy and composes engine chains:
  <https://mcpg.dev/docs/security/policy>
- Full gateway config schema, including `plugins[]` and `governance.policy`:
  <https://mcpg.dev/docs/reference/configuration>
- Sibling engines with the same wiring: `libs/plugins/security/policy-cedar`,
  `libs/plugins/security/policy-opa`
