//! Operator-supplied configuration schema for `dev.mcpg.policy.casbin`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CasbinConfig {
    /// Path to the Casbin model file (`.conf`).
    pub model_path: String,
    /// Path to the Casbin policy file (`.csv`).
    pub policy_path: String,
    /// Translation rules — how MCPG's evaluation envelope maps to
    /// Casbin's request tuple.
    pub translation: TranslationConfig,
    /// Optional. Default-deny convention (no policy matched).
    #[serde(default)]
    pub evaluation: EvaluationConfig,

    /// Optional bundle hot-reload watcher. Default disabled
    /// (operator restarts to pick up policy changes — same as
    /// pre-reload behavior). When enabled, the plugin polls
    /// `model_path` + `policy_path` every `check_interval_sec`
    /// and atomically swaps the Enforcer on detected changes.
    #[serde(default)]
    pub reload: ReloadConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReloadConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_check_interval_sec")]
    pub check_interval_sec: u64,
}

impl Default for ReloadConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval_sec: default_check_interval_sec(),
        }
    }
}

fn default_check_interval_sec() -> u64 {
    60
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranslationConfig {
    /// One entry per field in the model's `request_definition`.
    /// Walked in order to build the Casbin request tuple.
    pub request_fields: Vec<RequestField>,
}

/// Source for a single field in the request tuple.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum RequestField {
    /// `context.identity.subject_id` (or fallback if absent).
    IdentitySubjectId {
        #[serde(default)]
        fallback: Option<String>,
    },
    /// `context.identity.kind` / `trust_level` / `auth_provider`
    /// / `issuer`.
    IdentityKind {
        #[serde(default)]
        fallback: Option<String>,
    },
    IdentityTrustLevel {
        #[serde(default)]
        fallback: Option<String>,
    },
    IdentityAuthProvider {
        #[serde(default)]
        fallback: Option<String>,
    },
    IdentityIssuer {
        #[serde(default)]
        fallback: Option<String>,
    },
    /// `context.identity.attributes[<key>]` (or fallback).
    IdentityAttribute {
        key: String,
        #[serde(default)]
        fallback: Option<String>,
    },
    /// `context.tool_name` / `surface` / `transport` /
    /// `request_id` / `session_id`.
    Context {
        field: ContextField,
        #[serde(default)]
        fallback: Option<String>,
    },
    /// The literal `decision_point` string.
    DecisionPoint,
    /// `input.pointer(json_pointer)` — non-string values are
    /// stringified via `serde_json::to_string`.
    Input {
        json_pointer: String,
        #[serde(default)]
        fallback: Option<String>,
    },
    /// Operator-supplied constant string.
    Literal { value: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContextField {
    ToolName,
    Surface,
    Transport,
    RequestId,
    SessionId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationConfig {
    /// Default-deny convention.
    #[serde(default = "default_on_default_deny")]
    pub on_default_deny: DefaultDenyMode,
}

impl Default for EvaluationConfig {
    fn default() -> Self {
        Self {
            on_default_deny: default_on_default_deny(),
        }
    }
}

fn default_on_default_deny() -> DefaultDenyMode {
    DefaultDenyMode::NotApplicable
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DefaultDenyMode {
    /// Map default-deny to `PolicyEffect::NotApplicable`. Lets
    /// chained policy plugins try after this one. Default — fits
    /// composition.
    NotApplicable,
    /// Map default-deny to `PolicyEffect::Deny`. Strict-cedar-
    /// style; chains break here.
    Deny,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid policy.casbin config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("policy.casbin: model_path is empty")]
    EmptyModelPath,
    #[error("policy.casbin: policy_path is empty")]
    EmptyPolicyPath,
    #[error(
        "policy.casbin: translation.request_fields must be non-empty; \
         operator must declare one entry per field in the model's \
         request_definition"
    )]
    EmptyRequestFields,
    #[error(
        "policy.casbin: input source at request_fields[{index}] requires \
         a non-empty json_pointer"
    )]
    EmptyInputJsonPointer { index: usize },
    #[error(
        "policy.casbin: literal source at request_fields[{index}] requires \
         a non-empty value"
    )]
    EmptyLiteralValue { index: usize },
    #[error(
        "policy.casbin: identity_attribute source at request_fields[{index}] \
         requires a non-empty key"
    )]
    EmptyAttributeKey { index: usize },
}

impl CasbinConfig {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.model_path.trim().is_empty() {
            return Err(ConfigError::EmptyModelPath);
        }
        if self.policy_path.trim().is_empty() {
            return Err(ConfigError::EmptyPolicyPath);
        }
        if self.translation.request_fields.is_empty() {
            return Err(ConfigError::EmptyRequestFields);
        }
        for (index, field) in self.translation.request_fields.iter().enumerate() {
            match field {
                RequestField::Input { json_pointer, .. } if json_pointer.is_empty() => {
                    return Err(ConfigError::EmptyInputJsonPointer { index });
                }
                RequestField::Literal { value } if value.is_empty() => {
                    return Err(ConfigError::EmptyLiteralValue { index });
                }
                RequestField::IdentityAttribute { key, .. } if key.is_empty() => {
                    return Err(ConfigError::EmptyAttributeKey { index });
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_minimal_config() {
        let cfg = json!({
            "model_path": "/tmp/m.conf",
            "policy_path": "/tmp/p.csv",
            "translation": {
                "request_fields": [
                    { "source": "identity_subject_id", "fallback": "anonymous" },
                    { "source": "input", "json_pointer": "/path", "fallback": "/" },
                    { "source": "decision_point" }
                ]
            }
        })
        .to_string();
        let parsed = CasbinConfig::parse(&cfg).unwrap();
        assert_eq!(parsed.translation.request_fields.len(), 3);
        assert_eq!(
            parsed.evaluation.on_default_deny,
            DefaultDenyMode::NotApplicable
        );
    }

    #[test]
    fn rejects_empty_model_path() {
        let cfg = json!({
            "model_path": "",
            "policy_path": "p",
            "translation": { "request_fields": [{ "source": "decision_point" }] }
        })
        .to_string();
        let err = CasbinConfig::parse(&cfg).unwrap_err();
        matches!(err, ConfigError::EmptyModelPath);
    }

    #[test]
    fn rejects_empty_request_fields() {
        let cfg = json!({
            "model_path": "m",
            "policy_path": "p",
            "translation": { "request_fields": [] }
        })
        .to_string();
        let err = CasbinConfig::parse(&cfg).unwrap_err();
        matches!(err, ConfigError::EmptyRequestFields);
    }

    #[test]
    fn rejects_empty_input_json_pointer() {
        let cfg = json!({
            "model_path": "m",
            "policy_path": "p",
            "translation": {
                "request_fields": [{ "source": "input", "json_pointer": "" }]
            }
        })
        .to_string();
        let err = CasbinConfig::parse(&cfg).unwrap_err();
        matches!(err, ConfigError::EmptyInputJsonPointer { .. });
    }

    #[test]
    fn parses_all_source_kinds() {
        let cfg = json!({
            "model_path": "m",
            "policy_path": "p",
            "translation": {
                "request_fields": [
                    { "source": "identity_subject_id" },
                    { "source": "identity_kind" },
                    { "source": "identity_trust_level" },
                    { "source": "identity_auth_provider" },
                    { "source": "identity_issuer" },
                    { "source": "identity_attribute", "key": "tenant" },
                    { "source": "context", "field": "tool_name" },
                    { "source": "decision_point" },
                    { "source": "input", "json_pointer": "/x" },
                    { "source": "literal", "value": "foo" }
                ]
            }
        })
        .to_string();
        let parsed = CasbinConfig::parse(&cfg).unwrap();
        assert_eq!(parsed.translation.request_fields.len(), 10);
    }
}
