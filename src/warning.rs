use crate::model::{Analysis, Confidence, Severity};

pub fn human_report(analysis: &Analysis) -> String {
    let mut out = String::new();
    out.push_str("CommandGuard analysis\n");
    out.push_str("=====================\n");
    out.push_str(&format!("Severity: {:?}\n", analysis.severity));
    out.push_str(&format!("Confidence: {:?}\n\n", analysis.confidence));
    out.push_str(&analysis.explanation);
    if !analysis.explanation.ends_with('\n') {
        out.push('\n');
    }

    if !analysis.effects.is_empty() {
        out.push_str("\nEffects:\n");
        for effect in &analysis.effects {
            out.push_str(&format!("- {}\n", effect.label()));
        }
    }

    if !analysis.evidence.is_empty() {
        out.push_str("\nEvidence:\n");
        for item in &analysis.evidence {
            out.push_str("- ");
            out.push_str(&format!(
                "SOURCE: {}; TRANSFORM: {}; SINK: {}; EFFECT: {:?}; CONFIDENCE: {:?}\n",
                item.source.as_deref().unwrap_or("none"),
                item.transform.as_deref().unwrap_or("none"),
                item.sink.as_deref().unwrap_or("none"),
                item.effect,
                item.confidence
            ));
            out.push_str(&format!("  {}\n", item.reason));
        }
    }

    if !analysis.decoded_variants.is_empty() {
        out.push_str("\nDecoded variants:\n");
        for variant in &analysis.decoded_variants {
            out.push_str(&format!("- {}\n", variant.transform));
            out.push_str("```\n");
            out.push_str(&variant.text);
            if !variant.text.ends_with('\n') {
                out.push('\n');
            }
            out.push_str("```\n");
            if variant.truncated {
                out.push_str("  output truncated for display\n");
            }
        }
    }

    if !analysis.unsupported_constructs.is_empty() {
        out.push_str("\nUnsupported constructs:\n");
        for construct in &analysis.unsupported_constructs {
            out.push_str(&format!("- {construct}\n"));
        }
    }

    out
}

pub fn paste_warning(analysis: &Analysis, contains_newline: bool, show_decoded: bool) -> String {
    let mut out = String::new();
    out.push_str("\r\nCommandGuard blocked a suspicious paste\r\n");
    out.push_str(&format!(
        "Severity: {:?}    Confidence: {:?}\r\n\r\n",
        analysis.severity, analysis.confidence
    ));

    if analysis.severity == Severity::Safe && contains_newline {
        out.push_str("This paste contains a newline and may execute immediately.\r\n");
    } else {
        for line in analysis.explanation.lines() {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }

    if !analysis.effects.is_empty() {
        out.push_str("\r\nObserved effects:\r\n");
        for effect in &analysis.effects {
            out.push_str("- ");
            out.push_str(effect.label());
            out.push_str("\r\n");
        }
    }

    if analysis.confidence == Confidence::Unknown {
        out.push_str("\r\nSome shell constructs were outside the v0.1 analyzer.\r\n");
    }

    if show_decoded && !analysis.decoded_variants.is_empty() {
        out.push_str("\r\nDecoded command text:\r\n");
        for variant in &analysis.decoded_variants {
            out.push_str("--- ");
            out.push_str(&variant.transform);
            out.push_str(" ---\r\n");
            for line in variant.text.lines() {
                out.push_str(line);
                out.push_str("\r\n");
            }
        }
    }

    out.push_str("\r\n[c] Cancel    [s] Show decoded command    [e] Execute anyway\r\n");
    out
}
