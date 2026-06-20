use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Safe,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn should_interrupt(self) -> bool {
        matches!(self, Severity::Medium | Severity::High)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Confidence {
    Unknown,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EffectKind {
    RemoteDownload,
    DynamicExecution,
    ConcealedPayload,
    CredentialRead,
    PersistenceWrite,
    PrivilegeEscalation,
    DestructiveFilesystem,
    ExternalTransmission,
}

impl EffectKind {
    pub fn label(&self) -> &'static str {
        match self {
            EffectKind::RemoteDownload => "Remote download",
            EffectKind::DynamicExecution => "Dynamic execution",
            EffectKind::ConcealedPayload => "Concealed payload",
            EffectKind::CredentialRead => "Credential read",
            EffectKind::PersistenceWrite => "Persistence write",
            EffectKind::PrivilegeEscalation => "Privilege escalation",
            EffectKind::DestructiveFilesystem => "Destructive filesystem operation",
            EffectKind::ExternalTransmission => "External transmission",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub source: Option<String>,
    pub transform: Option<String>,
    pub sink: Option<String>,
    pub effect: EffectKind,
    pub confidence: Confidence,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedVariant {
    pub transform: String,
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Analysis {
    pub severity: Severity,
    pub confidence: Confidence,
    pub effects: Vec<EffectKind>,
    pub evidence: Vec<Evidence>,
    pub decoded_variants: Vec<DecodedVariant>,
    pub unsupported_constructs: Vec<String>,
    pub explanation: String,
}

impl Analysis {
    pub fn safe() -> Self {
        Self {
            severity: Severity::Safe,
            confidence: Confidence::High,
            effects: Vec::new(),
            evidence: Vec::new(),
            decoded_variants: Vec::new(),
            unsupported_constructs: Vec::new(),
            explanation: "No suspicious pasted-command effects were identified.".to_string(),
        }
    }
}
