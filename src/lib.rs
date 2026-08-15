//! `dev.mcpg.policy.casbin` — Casbin `policy_engine` plugin.
//!
//! This crate is the implementation; operator-facing
//! summary lives in `README.md`.
//!
//! # v0.1 scope (current)
//!
//! - Embedded Casbin Enforcer (in-process via `casbin-rs`).
//! - Operator-supplied model + policy files (from disk at boot).
//! - Configurable translation from `(decision_point, input,
//!   context)` → variable-arity Casbin request tuple.
//! - Decision mapping: Allow / Deny (with
//!   matched-policy reason) / NotApplicable (default-deny).
//! - `policy_version()` SHA-256 of `<model> || <policy>`.
//!
//! # Deferred (v0.2)
//!
//! - Bundle reload (mtime/sha256 polling + arc_swap). v0.1
//!   requires a gateway restart to pick up policy changes — same
//!   as the OPA plugin's pre-reload behavior.
//! - Eval cache (the casbin `cached` feature flag).
//! - Adapter-based dynamic policies (SQL / Redis adapters).

mod config;

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use casbin::{CoreApi, DefaultModel, Enforcer, FileAdapter};
use mcpg_bundle_reload::{BundleReload, BundleSource, ReloadError};
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::policy::{PolicyDecision, PolicyEffect, PolicyVersion};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{PluginClass, PluginContext, PluginManifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncPolicyEngine;
use serde_json::Value;
use tokio::runtime::Runtime;

pub use config::{
    CasbinConfig, ConfigError, ContextField, DefaultDenyMode, EvaluationConfig, ReloadConfig,
    RequestField, TranslationConfig,
};

const PLUGIN_ID: &str = "dev.mcpg.policy.casbin";
const ENGINE_NAME: &str = "casbin";

pub struct CasbinPolicyPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    config: CasbinConfig,
    /// Hot-reloadable Enforcer. Wrapped via the shared
    /// bundle-reload helper's async-parser variant so casbin-rs's
    /// `Enforcer::new(model, adapter).await` constructor fits
    /// naturally.
    enforcer: BundleReload<Enforcer>,
    /// Bundled tokio runtime — `evaluate` is sync per
    /// `SyncPolicyEngine`; casbin-rs's APIs are async because of
    /// the `runtime-tokio` feature flag. Always present (even
    /// for static-only deploys) since enforcer construction is
    /// async.
    runtime: Runtime,
    /// Cluster client (v20 ABI) handed at `make` time when the
    /// operator has registered a `cluster_backend`. When
    /// bound, emits a startup heartbeat on
    /// `policy.casbin.policies-loaded` carrying the bundle
    /// fingerprint AND subscribes to the same topic so a peer's
    /// successful reload triggers an out-of-band poll on this
    /// node — closing the multi-instance bundle-reload divergence
    /// gap.
    #[allow(dead_code)]
    cluster: Option<mcpg_plugin_sdk::ClusterClient>,
    /// Active subscription on `policy.casbin.policies-loaded`.
    /// Held for the plugin's lifetime; Drop cancels the stream.
    #[allow(dead_code)]
    cluster_subscription: Option<mcpg_plugin_sdk::Subscription<mcpg_cluster_api::PublishedMessage>>,
    /// The unified host surface. Installed once at boot
    /// by the SDK factory via
    /// [`CasbinPolicyPlugin::set_host_handle`] before any `evaluate`
    /// traffic flows. When `None` (test harnesses), the per-call
    /// HostHandle observability triad short-circuits to no-ops and
    /// the plugin's existing internal `tracing::*` + `metrics::*`
    /// calls carry the load.
    host_handle: OnceLock<HostHandle>,
}

impl CasbinPolicyPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        Self::from_config_json_with_cluster(config_json, None)
    }

    /// v20 ABI factory — receives the optional cluster client from
    /// the SDK macro. Public so unit tests can construct the
    /// plugin with a synthetic client.
    pub fn from_config_json_with_cluster(
        config_json: &str,
        cluster: Option<mcpg_plugin_sdk::ClusterClient>,
    ) -> Self {
        let cfg = CasbinConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "casbin policy: config parse failed; refusing to register"
            );
            panic!(
                "casbin policy config parse failed: {err}. A misconfigured \
                 policy engine is a security hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg, cluster)
    }

    fn from_validated_config(
        cfg: CasbinConfig,
        cluster: Option<mcpg_plugin_sdk::ClusterClient>,
    ) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("casbin policy: failed to build tokio runtime");

        // Cross-check request-field arity once at boot before
        // spawning the watcher — a misconfigured plugin should
        // fail fast, not after a successful first parse.
        let model = runtime
            .block_on(async { DefaultModel::from_file(&cfg.model_path).await })
            .unwrap_or_else(|err| {
                panic!(
                    "casbin policy: failed to parse model file `{}`: {err}",
                    cfg.model_path
                )
            });
        validate_request_arity(&model, &cfg.translation.request_fields);

        let source = BundleSource::Files(vec![
            cfg.model_path.clone().into(),
            cfg.policy_path.clone().into(),
        ]);

        let model_path = cfg.model_path.clone();
        let policy_path = cfg.policy_path.clone();
        let parser = move |_source: BundleSource| -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Enforcer, ReloadError>> + Send>,
        > {
            let model_path = model_path.clone();
            let policy_path = policy_path.clone();
            Box::pin(async move {
                let model = DefaultModel::from_file(&model_path)
                    .await
                    .map_err(|e| ReloadError::Parse(format!("casbin model parse failed: {e}")))?;
                let adapter = FileAdapter::new(policy_path);
                Enforcer::new(model, adapter)
                    .await
                    .map_err(|e| ReloadError::Parse(format!("casbin enforcer build failed: {e}")))
            })
        };

        let enforcer = if cfg.reload.enabled {
            let interval = Duration::from_secs(cfg.reload.check_interval_sec);
            runtime
                .block_on(async { mcpg_bundle_reload::start_async(source, parser, interval).await })
                .unwrap_or_else(|err| panic!("casbin policy: failed to load bundle: {err}"))
        } else {
            // Static-only path: build the enforcer once, wrap.
            let parsed = runtime
                .block_on(async { parser(source.clone()).await })
                .unwrap_or_else(|err| panic!("casbin policy: failed to load bundle: {err}"));
            let fingerprint = runtime
                .block_on(async { source.fingerprint().await })
                .unwrap_or_else(|err| panic!("casbin policy: failed to fingerprint bundle: {err}"));
            mcpg_bundle_reload::static_only(parsed, fingerprint)
        };

        // Cluster opt-in.
        // When a coordinator is bound, subscribe to the policies-
        // loaded topic FIRST (so we don't miss the local self-
        // publish), then emit our own heartbeat carrying the bundle
        // fingerprint. Subscriber compares peer fingerprint to
        // local fingerprint; on mismatch, pokes the BundleReload
        // so the watcher runs an out-of-band poll. Closes the
        // multi-instance bundle-reload divergence gap. Failures
        // are logged and swallowed — best-effort coordination
        // never blocks plugin registration.
        let mut subscription = None;
        if let Some(client) = &cluster {
            let info = client.node_info();
            let local_node_id = info.node_id.clone();
            let poke_handle = enforcer.poke_handle();
            let bundle_for_subscriber = enforcer.clone();
            tracing::info!(
                plugin_id = PLUGIN_ID,
                cluster_node_id = %info.node_id,
                cluster_address = %info.address,
                "casbin policy: cluster coordinator bound"
            );

            match client.subscribe("policy.casbin.policies-loaded", None, None, move |msg| {
                let from = msg.from_node.clone();
                if from == local_node_id {
                    return; // self-publish — already logged
                }
                let peer_fp = serde_json::from_slice::<serde_json::Value>(&msg.payload)
                    .ok()
                    .and_then(|v| {
                        v.get("fingerprint")
                            .and_then(|f| f.as_str())
                            .map(str::to_owned)
                    });
                let local_fp = bundle_for_subscriber.fingerprint();
                let should_poke = match &peer_fp {
                    Some(peer) => peer != &local_fp,
                    None => true,
                };
                tracing::info!(
                    plugin_id = PLUGIN_ID,
                    from_node = %from,
                    topic = %msg.topic,
                    peer_fingerprint = ?peer_fp,
                    local_fingerprint = %local_fp,
                    poked = should_poke,
                    "casbin policy: peer reloaded policies"
                );
                if should_poke {
                    poke_handle.poke();
                }
            }) {
                Ok(s) => subscription = Some(s),
                Err(e) => tracing::warn!(
                    plugin_id = PLUGIN_ID,
                    error = %e,
                    "casbin policy: subscription setup failed"
                ),
            }

            let payload = serde_json::json!({
                "plugin_id": PLUGIN_ID,
                "version": env!("CARGO_PKG_VERSION"),
                "fingerprint": enforcer.fingerprint(),
                "node_id": info.node_id,
            });
            let bytes = bytes::Bytes::from(serde_json::to_vec(&payload).unwrap_or_default());
            if let Err(e) = client.publish("policy.casbin.policies-loaded", None, bytes) {
                tracing::warn!(
                    plugin_id = PLUGIN_ID,
                    error = %e,
                    "casbin policy: heartbeat publish failed"
                );
            }
        }

        tracing::info!(
            plugin_id = PLUGIN_ID,
            model_path = %cfg.model_path,
            policy_path = %cfg.policy_path,
            request_arity = cfg.translation.request_fields.len(),
            reload_enabled = cfg.reload.enabled,
            cluster_bound = cluster.is_some(),
            "casbin policy: enforcer compiled"
        );

        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "Casbin Policy Engine".into(),
                    plugin_class: PluginClass::PolicyEngine,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                config: cfg,
                enforcer,
                runtime,
                cluster,
                cluster_subscription: subscription,
                host_handle: OnceLock::new(),
            }),
        }
    }

    /// Install the unified [`HostHandle`] surface for
    /// per-evaluation observability. Idempotent.
    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.inner.host_handle.set(host).is_ok()
    }

    /// Borrow the installed unified host surface.
    fn host_handle(&self) -> Option<&HostHandle> {
        self.inner.host_handle.get()
    }
}

/// Cross-check the model's declared request arity against
/// translation.request_fields. The model file may not be
/// directly introspectable for the count, so we use Casbin's
/// model API to count the `r` definition's params.
fn validate_request_arity(model: &DefaultModel, request_fields: &[RequestField]) {
    use casbin::Model;
    let model_arity = model
        .get_model()
        .get("r")
        .and_then(|sec| sec.get("r"))
        .map(|assertion| assertion.tokens.len())
        .unwrap_or(0);
    if model_arity == 0 {
        panic!(
            "casbin policy: model has no [request_definition] r section; \
             cannot determine request arity"
        );
    }
    if model_arity != request_fields.len() {
        panic!(
            "casbin policy: model declares {model_arity} request fields, \
             but translation.request_fields has {} entries — operator must \
             keep them in sync",
            request_fields.len()
        );
    }
}

fn now_marker() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("@{secs}")
}

fn current_policy_version(inner: &Inner) -> PolicyVersion {
    PolicyVersion {
        hash: inner.enforcer.fingerprint(),
        loaded_at: now_marker(),
        source: "casbin model+policy".to_owned(),
    }
}

/// Resolve a single field source against the request envelope.
/// Returns the string value Casbin will see in the request tuple.
fn resolve_field(
    field: &RequestField,
    decision_point: &str,
    input: &Value,
    context: &PluginContext,
) -> String {
    let fb = |fallback: &Option<String>| -> String { fallback.clone().unwrap_or_default() };
    match field {
        RequestField::IdentitySubjectId { fallback } => context
            .identity
            .subject_id
            .clone()
            .unwrap_or_else(|| fb(fallback)),
        RequestField::IdentityKind { fallback } => {
            if context.identity.kind.is_empty() {
                fb(fallback)
            } else {
                context.identity.kind.clone()
            }
        }
        RequestField::IdentityTrustLevel { fallback } => {
            if context.identity.trust_level.is_empty() {
                fb(fallback)
            } else {
                context.identity.trust_level.clone()
            }
        }
        RequestField::IdentityAuthProvider { fallback } => context
            .identity
            .auth_provider
            .clone()
            .unwrap_or_else(|| fb(fallback)),
        RequestField::IdentityIssuer { fallback } => context
            .identity
            .issuer
            .clone()
            .unwrap_or_else(|| fb(fallback)),
        RequestField::IdentityAttribute { key, fallback } => context
            .identity
            .attributes
            .get(key)
            .cloned()
            .unwrap_or_else(|| fb(fallback)),
        RequestField::Context { field, fallback } => {
            let v = match field {
                ContextField::ToolName => Some(&context.tool_name),
                ContextField::Surface => Some(&context.surface),
                ContextField::Transport => Some(&context.transport),
                ContextField::RequestId => Some(&context.request_id),
                ContextField::SessionId => context.session_id.as_ref(),
            };
            v.cloned()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| fb(fallback))
        }
        RequestField::DecisionPoint => decision_point.to_owned(),
        RequestField::Input {
            json_pointer,
            fallback,
        } => match input.pointer(json_pointer) {
            Some(v) => match v {
                Value::String(s) => s.clone(),
                Value::Null => fb(fallback),
                other => other.to_string(),
            },
            None => fb(fallback),
        },
        RequestField::Literal { value } => value.clone(),
    }
}

fn build_request(
    config: &CasbinConfig,
    decision_point: &str,
    input: &Value,
    context: &PluginContext,
) -> Vec<String> {
    config
        .translation
        .request_fields
        .iter()
        .map(|f| resolve_field(f, decision_point, input, context))
        .collect()
}

fn evaluate_request(
    plugin: &CasbinPolicyPlugin,
    decision_point: &str,
    input: &Value,
    context: &PluginContext,
) -> PolicyDecision {
    // Wrap evaluation in a plugin-scoped span so traces attribute
    // back to dev.mcpg.policy.casbin for per-plugin override.
    let _span = tracing::info_span!(
        "casbin_policy_evaluate",
        plugin_id = PLUGIN_ID,
        decision_point = %decision_point,
    )
    .entered();

    // Open a host-attributed span ALONGSIDE the
    // internal `info_span!` above. Attrs carry decision_point + the
    // current enforcer fingerprint (low-cardinality — one value per
    // loaded bundle), so operators can correlate decisions against
    // the active model/policy version.
    let policy_id = plugin.inner.enforcer.fingerprint();
    let host_span = plugin.host_handle().map(|h| {
        h.span(
            "policy_casbin.evaluate",
            serde_json::json!({
                "decision_point": decision_point,
                "policy_id": policy_id,
                "request_id": context.request_id,
            }),
        )
    });

    let started = std::time::Instant::now();
    let decision = evaluate_request_inner(&plugin.inner, decision_point, input, context);
    let elapsed = started.elapsed();

    let outcome = match decision.effect {
        PolicyEffect::Allow => "allow",
        PolicyEffect::Deny => "deny",
        PolicyEffect::NotApplicable => "not_applicable",
    };
    metrics::counter!(
        "mcpg_policy_casbin_decisions_total",
        "decision_point" => decision_point.to_owned(),
        "outcome" => outcome,
    )
    .increment(1);
    metrics::histogram!(
        "mcpg_policy_casbin_evaluate_ms",
        "decision_point" => decision_point.to_owned(),
    )
    .record(elapsed.as_millis() as f64);

    match decision.effect {
        PolicyEffect::Allow => tracing::debug!(
            decision_point = %decision_point,
            elapsed_ms = %elapsed.as_millis(),
            "casbin policy: allow"
        ),
        PolicyEffect::Deny => tracing::warn!(
            decision_point = %decision_point,
            reason = decision.reason.as_deref().unwrap_or(""),
            elapsed_ms = %elapsed.as_millis(),
            "casbin policy: deny"
        ),
        PolicyEffect::NotApplicable => tracing::debug!(
            decision_point = %decision_point,
            elapsed_ms = %elapsed.as_millis(),
            "casbin policy: not applicable"
        ),
    }

    // Unified host-observability triad. Runs ALONGSIDE
    // the internal metric / tracing calls above; the two coexist
    // intentionally until the host sinks subsume the internal calls.
    let outcome_label = host_outcome_label(&decision);
    plugin.emit_host_observability(decision_point, &decision, outcome_label, elapsed, context);

    drop(host_span);

    decision
}

/// Bounded host-side outcome label set:
/// `allow`, `deny`, `error`. `not_applicable` rolls into `allow`
/// because both let traffic through; operators wanting the four-way
/// breakdown read the internal `mcpg_policy_casbin_decisions_total`
/// counter. `error` fires when the enforcer itself failed —
/// casbin-rs maps such failures to Deny + reason starting with
/// `casbin enforce error:`.
fn host_outcome_label(decision: &PolicyDecision) -> &'static str {
    match decision.effect {
        PolicyEffect::Allow | PolicyEffect::NotApplicable => "allow",
        PolicyEffect::Deny => match decision.reason.as_deref() {
            Some(r) if r.starts_with("casbin enforce error:") => "error",
            _ => "deny",
        },
    }
}

fn evaluate_request_inner(
    inner: &Inner,
    decision_point: &str,
    input: &Value,
    context: &PluginContext,
) -> PolicyDecision {
    let request = build_request(&inner.config, decision_point, input, context);
    let version_hash = inner.enforcer.fingerprint();

    // Snapshot the enforcer once per call. arc_swap guarantees a
    // mid-evaluation reload doesn't affect this evaluation.
    let enforcer_snapshot = inner.enforcer.load();

    // enforce_ex returns (allowed, matched: Vec<Vec<String>>)
    // — outer Vec is one entry per matched policy line, inner
    // Vec is the policy line's columns. Empty outer Vec = no
    // policy matched (default-deny).
    let result: Result<(bool, Vec<Vec<String>>), casbin::Error> = inner.runtime.block_on(async {
        let req: Vec<&str> = request.iter().map(String::as_str).collect();
        enforcer_snapshot.enforce_ex(req)
    });

    match result {
        Ok((true, _matched)) => PolicyDecision {
            effect: PolicyEffect::Allow,
            reason: None,
            obligations: vec![],
            redactions: vec![],
            attributes: Default::default(),
            policy_version: version_hash,
        },
        Ok((false, matched)) if matched.is_empty() => {
            // Default-deny — no policy matched.
            match inner.config.evaluation.on_default_deny {
                DefaultDenyMode::NotApplicable => PolicyDecision {
                    effect: PolicyEffect::NotApplicable,
                    reason: None,
                    obligations: vec![],
                    redactions: vec![],
                    attributes: Default::default(),
                    policy_version: version_hash,
                },
                DefaultDenyMode::Deny => {
                    PolicyDecision::deny("casbin: default-deny (no policy matched)", &version_hash)
                }
            }
        }
        Ok((false, matched)) => {
            // Explicit deny via deny-override model. Surface
            // matched policy lines as the reason. (matched is
            // Vec<Vec<String>>; render each line as a CSV-style
            // join.)
            let rendered: Vec<String> = matched.iter().map(|line| line.join(", ")).collect();
            PolicyDecision::deny(format!("casbin: {}", rendered.join("; ")), &version_hash)
        }
        Err(err) => {
            tracing::warn!(
                plugin_id = PLUGIN_ID,
                decision_point = %decision_point,
                error = %err,
                "casbin policy: enforce error; denying request"
            );
            PolicyDecision::deny(format!("casbin enforce error: {err}"), &version_hash)
        }
    }
}

impl CasbinPolicyPlugin {
    /// Emit the per-evaluation host-observability triad:
    /// latency histogram + decisions counter + Deny / Error audit
    /// event, through the installed [`HostHandle`]. Short-circuits
    /// when no handle is installed.
    ///
    /// Cardinality budget: outcome ∈ {allow, deny, error}.
    ///
    /// Audit emission is gated to `deny` / `error`:
    ///
    /// - `dev.mcpg.policy.casbin.deny` on rule-driven Deny
    ///   (casbin's `enforce_ex` exposes matched policy lines —
    ///   those flow into `details.matched_rules`).
    /// - `dev.mcpg.policy.casbin.error` on enforcer error
    ///   (casbin-rs returns Err from `enforce_ex`).
    ///
    /// Allow + NotApplicable do NOT audit-emit.
    fn emit_host_observability(
        &self,
        decision_point: &str,
        decision: &PolicyDecision,
        outcome_label: &'static str,
        duration: std::time::Duration,
        context: &PluginContext,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        let elapsed_secs = duration.as_secs_f64();
        host.histogram(
            "mcpg_policy_casbin_latency_seconds",
            elapsed_secs,
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_policy_casbin_decisions_total",
            1,
            &[("outcome", outcome_label)],
        );

        let action: Option<&'static str> = match outcome_label {
            "deny" => Some("dev.mcpg.policy.casbin.deny"),
            "error" => Some("dev.mcpg.policy.casbin.error"),
            _ => None,
        };
        let Some(action) = action else {
            return;
        };

        let audit_outcome = match outcome_label {
            "error" => AuditOutcome::Failure,
            _ => AuditOutcome::Denied,
        };

        // Casbin's `enforce_ex` exposes matched policy lines as
        // `Vec<Vec<String>>` — the plugin already flattens them
        // into the decision `reason` as a `;`-joined string
        // prefixed with `casbin: `. Surface that to audit details
        // as a structured array so operators can filter on
        // individual matched rules.
        //
        // The default-deny path stamps a synthetic reason
        // (`"casbin: default-deny (no policy matched)"`) which
        // doesn't carry any matched rules — strip it so the
        // audit shape is "deny with empty matched_rules" rather
        // than "deny matched a rule named 'default-deny ...'".
        let matched_rules: Vec<String> = match decision.reason.as_deref() {
            Some(r) if r.starts_with("casbin: ") && !r.contains("default-deny") => r
                .trim_start_matches("casbin: ")
                .split(';')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect(),
            _ => Vec::new(),
        };

        let subject = context
            .identity
            .subject_id
            .clone()
            .unwrap_or_else(|| "anonymous".to_owned());
        let resource_uri = format!("tool://{}/{}", context.tool_name, decision_point);

        let details = serde_json::json!({
            "engine": ENGINE_NAME,
            "decision_point": decision_point,
            "subject": subject,
            "resource": resource_uri,
            "matched_rules": matched_rules,
            "reason": decision.reason.clone().unwrap_or_default(),
            "policy_version": decision.policy_version.clone(),
            "duration_ms": duration.as_millis() as u64,
            "alias": host.alias(),
        });

        let actor = if context.identity.kind.is_empty() {
            synthetic_system_identity()
        } else {
            context.identity.clone()
        };

        let event = AuditEvent {
            event_id: format!("casbin-{}-{}", context.request_id, duration.as_nanos()),
            occurred_at: rfc3339_now_millis(),
            actor,
            action: action.to_owned(),
            resource: Some(resource_uri),
            outcome: audit_outcome,
            request_id: Some(context.request_id.clone()),
            node_id: None,
            details,
            prev_event_hash: None,
        };
        // SyncPolicyEngine::evaluate is sync; the gateway
        // dispatches it from a `spawn_blocking` worker (see L.10
        // reference). Calling HostHandle::audit_event directly is
        // safe — the host's internal `block_on` lands on a
        // blocking thread, not a tokio worker.
        if let Err(err) = host.audit_event(event) {
            tracing::debug!(
                target: "mcpg::policy::casbin::host_handle",
                error = %err,
                "host_handle.audit_event emission failed"
            );
        }
    }
}

impl SyncPolicyEngine for CasbinPolicyPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn name(&self) -> &str {
        ENGINE_NAME
    }

    fn evaluate(
        &self,
        decision_point: &str,
        input: &Value,
        context: &PluginContext,
    ) -> PolicyDecision {
        evaluate_request(self, decision_point, input, context)
    }

    fn policy_version(&self) -> PolicyVersion {
        current_policy_version(&self.inner)
    }
}

#[mcpg_plugin_protocol::async_trait]
impl mcpg_plugin_protocol::policy::PolicyEngine for CasbinPolicyPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn name(&self) -> &str {
        ENGINE_NAME
    }

    async fn evaluate(
        &self,
        decision_point: &str,
        input: &Value,
        context: &PluginContext,
    ) -> PolicyDecision {
        evaluate_request(self, decision_point, input, context)
    }

    async fn policy_version(&self) -> PolicyVersion {
        current_policy_version(&self.inner)
    }
}

/// RFC 3339 timestamp with millisecond precision for audit
/// `occurred_at`. Mirrors the helper in the other policy plugins.
fn rfc3339_now_millis() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let millis = now.subsec_millis();
    let (year, month, day, hour, min, sec) = epoch_to_ymdhms(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// Naïve epoch → (Y, M, D, h, m, s). Mirrors the helper in
/// policy-opa / policy-cedar so this crate doesn't pull `chrono`.
fn epoch_to_ymdhms(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days_since_epoch = secs.div_euclid(86_400);
    let secs_today = secs.rem_euclid(86_400) as u32;
    let hour = secs_today / 3600;
    let min = (secs_today % 3600) / 60;
    let sec = secs_today % 60;
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, min, sec)
}

/// Synthetic identity for system-attributed audit events.
fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some(PLUGIN_ID.into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

declare_plugin! {
    plugin_id: "dev.mcpg.policy.casbin",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        policy_engine as policy {
            inner_name: "",
            plugin_type: CasbinPolicyPlugin,
            // Install the unified `HostHandle` on the
            // plugin so per-evaluation observability (span +
            // latency histogram + decisions counter + Deny / Error
            // audit events) routes through the gateway's central
            // host-services sink. Idempotent — a second install
            // returns false and the slot remains untouched.
            factory: |cfg: &str, host: ::mcpg_plugin_sdk::HostHandle| -> CasbinPolicyPlugin {
                let plugin = CasbinPolicyPlugin::from_config_json_with_cluster(
                    cfg,
                    host.cluster(),
                );
                let _installed = plugin.set_host_handle(host);
                plugin
            },
        }
    ],
}

// silence unused-warning for PluginIdentity import that keeps the
// trait bounds visible in IDEs
#[allow(dead_code)]
fn _identity_marker(_: &PluginIdentity) {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::io::Write;

    use std::sync::atomic::{AtomicUsize, Ordering};
    static FIXTURE_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn write_fixture(name: &str, content: &str) -> std::path::PathBuf {
        let n = FIXTURE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("mcpg-casbin-test-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.txt"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    fn acl_model() -> &'static str {
        // Standard ACL model from Casbin examples.
        "[request_definition]\n\
         r = sub, obj, act\n\
         \n\
         [policy_definition]\n\
         p = sub, obj, act\n\
         \n\
         [policy_effect]\n\
         e = some(where (p.eft == allow))\n\
         \n\
         [matchers]\n\
         m = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n"
    }

    fn rbac_model() -> &'static str {
        "[request_definition]\n\
         r = sub, obj, act\n\
         \n\
         [policy_definition]\n\
         p = sub, obj, act\n\
         \n\
         [role_definition]\n\
         g = _, _\n\
         \n\
         [policy_effect]\n\
         e = some(where (p.eft == allow))\n\
         \n\
         [matchers]\n\
         m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act\n"
    }

    fn build(
        model_content: &str,
        policy_content: &str,
        translation: serde_json::Value,
    ) -> CasbinPolicyPlugin {
        let m = write_fixture("model", model_content);
        let p = write_fixture("policy", policy_content);
        let cfg = json!({
            "model_path": m.to_string_lossy().to_string(),
            "policy_path": p.to_string_lossy().to_string(),
            "translation": translation,
        });
        CasbinPolicyPlugin::from_config_json(&cfg.to_string())
    }

    fn ctx(subject: &str, roles: &[&str]) -> PluginContext {
        PluginContext {
            request_id: "r1".into(),
            session_id: None,
            tool_name: "tool".into(),
            surface: "tool".into(),
            identity: PluginIdentity {
                kind: "verified".into(),
                trust_level: "verified".into(),
                subject_id: Some(subject.into()),
                auth_provider: None,
                issuer: None,
                roles: roles.iter().map(|s| (*s).to_owned()).collect(),
                groups: vec![],
                scopes: vec![],
                attributes: BTreeMap::new(),
            },
            transport: "http".into(),
        }
    }

    fn standard_translation() -> serde_json::Value {
        json!({
            "request_fields": [
                { "source": "identity_subject_id", "fallback": "anonymous" },
                { "source": "input", "json_pointer": "/path", "fallback": "/" },
                { "source": "decision_point" }
            ]
        })
    }

    #[test]
    fn acl_allow_for_matching_rule() {
        let plugin = build(
            acl_model(),
            "p, alice, /data1, read\n",
            standard_translation(),
        );
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "read",
            &json!({ "path": "/data1" }),
            &ctx("alice", &[]),
        );
        assert_eq!(dec.effect, PolicyEffect::Allow);
    }

    #[test]
    fn acl_default_deny_maps_to_not_applicable() {
        let plugin = build(
            acl_model(),
            "p, alice, /data1, read\n",
            standard_translation(),
        );
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "read",
            &json!({ "path": "/other" }),
            &ctx("alice", &[]),
        );
        assert_eq!(dec.effect, PolicyEffect::NotApplicable);
    }

    #[test]
    fn acl_default_deny_can_be_strict() {
        let m = write_fixture("model", acl_model());
        let p = write_fixture("policy", "p, alice, /data1, read\n");
        let cfg = json!({
            "model_path": m.to_string_lossy().to_string(),
            "policy_path": p.to_string_lossy().to_string(),
            "translation": standard_translation(),
            "evaluation": { "on_default_deny": "deny" }
        });
        let plugin = CasbinPolicyPlugin::from_config_json(&cfg.to_string());
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "read",
            &json!({ "path": "/other" }),
            &ctx("alice", &[]),
        );
        assert_eq!(dec.effect, PolicyEffect::Deny);
        assert!(dec.reason.unwrap().contains("default-deny"));
    }

    #[test]
    fn rbac_allow_via_role_grouping() {
        let plugin = build(
            rbac_model(),
            "p, admin, /data1, read\n\
             g, alice, admin\n",
            standard_translation(),
        );
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "read",
            &json!({ "path": "/data1" }),
            &ctx("alice", &[]),
        );
        assert_eq!(dec.effect, PolicyEffect::Allow);
    }

    #[test]
    fn rbac_denies_when_user_not_in_role() {
        let plugin = build(
            rbac_model(),
            "p, admin, /data1, read\n\
             g, alice, admin\n",
            standard_translation(),
        );
        let dec = SyncPolicyEngine::evaluate(
            &plugin,
            "read",
            &json!({ "path": "/data1" }),
            &ctx("bob", &[]), // not in admin
        );
        assert_eq!(dec.effect, PolicyEffect::NotApplicable);
    }

    #[test]
    fn translation_uses_fallback_when_field_absent() {
        let plugin = build(
            acl_model(),
            "p, anonymous, /public, read\n",
            standard_translation(),
        );
        let mut c = ctx("alice", &[]);
        c.identity.subject_id = None; // forces fallback
        let dec = SyncPolicyEngine::evaluate(&plugin, "read", &json!({ "path": "/public" }), &c);
        assert_eq!(dec.effect, PolicyEffect::Allow);
    }

    #[test]
    fn policy_version_hash_changes_with_policy_content() {
        let plugin1 = build(
            acl_model(),
            "p, alice, /data1, read\n",
            standard_translation(),
        );
        let plugin2 = build(
            acl_model(),
            "p, alice, /data1, write\n",
            standard_translation(),
        );
        assert_ne!(
            plugin1.inner.enforcer.fingerprint(),
            plugin2.inner.enforcer.fingerprint()
        );
    }

    #[test]
    fn policy_version_fingerprint_is_stable_for_same_plugin_instance() {
        // Bundle-reload's fingerprint hashes (path || bytes) per
        // file, so two plugin instances at different temp paths
        // produce different fingerprints even with same bytes.
        // The stability guarantee is per-instance: querying
        // fingerprint() twice on the same plugin returns the
        // same value.
        let plugin = build(
            acl_model(),
            "p, alice, /data1, read\n",
            standard_translation(),
        );
        let fp1 = plugin.inner.enforcer.fingerprint();
        let fp2 = plugin.inner.enforcer.fingerprint();
        assert_eq!(fp1, fp2);
    }

    #[test]
    #[should_panic(expected = "translation.request_fields has 4 entries")]
    fn arity_mismatch_panics_at_boot() {
        let m = write_fixture("model", acl_model());
        let p = write_fixture("policy", "");
        // ACL model declares 3 request fields (sub, obj, act);
        // give 4.
        let cfg = json!({
            "model_path": m.to_string_lossy().to_string(),
            "policy_path": p.to_string_lossy().to_string(),
            "translation": {
                "request_fields": [
                    { "source": "identity_subject_id" },
                    { "source": "decision_point" },
                    { "source": "decision_point" },
                    { "source": "decision_point" }
                ]
            }
        });
        let _ = CasbinPolicyPlugin::from_config_json(&cfg.to_string());
    }
}
