use crate::analyzer::Analyzer;
use crate::model::Severity;
use anyhow::Context;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct BenchReport {
    pub total: usize,
    pub malicious: usize,
    pub benign: usize,
    pub true_positive: usize,
    pub false_positive: usize,
    pub true_negative: usize,
    pub false_negative: usize,
    pub skipped: usize,
}

impl BenchReport {
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("CommandGuard bench\n");
        out.push_str("==================\n");
        out.push_str(&format!("Total cases: {}\n", self.total));
        out.push_str(&format!("Malicious cases: {}\n", self.malicious));
        out.push_str(&format!("Benign cases: {}\n", self.benign));
        out.push_str(&format!("Skipped cases: {}\n\n", self.skipped));
        out.push_str(&format!("True positives: {}\n", self.true_positive));
        out.push_str(&format!("False positives: {}\n", self.false_positive));
        out.push_str(&format!("True negatives: {}\n", self.true_negative));
        out.push_str(&format!("False negatives: {}\n", self.false_negative));

        if self.malicious > 0 {
            let recall = self.true_positive as f64 / self.malicious as f64;
            out.push_str(&format!("Recall: {:.1}%\n", recall * 100.0));
        }
        if self.benign > 0 {
            let fpr = self.false_positive as f64 / self.benign as f64;
            out.push_str(&format!("False positive rate: {:.1}%\n", fpr * 100.0));
        }

        out
    }
}

pub fn run(root: &Path) -> anyhow::Result<BenchReport> {
    let analyzer = Analyzer::default();
    let mut report = BenchReport::default();
    let mut files = Vec::new();
    collect_files(root, &mut files)?;

    for file in files {
        let expected = expected_label(root, &file);
        let Some(expected_malicious) = expected else {
            report.skipped += 1;
            continue;
        };

        let input = fs::read_to_string(&file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        let analysis = analyzer.analyze(&input);
        let detected = analysis.severity >= Severity::Medium;

        report.total += 1;
        if expected_malicious {
            report.malicious += 1;
            if detected {
                report.true_positive += 1;
            } else {
                report.false_negative += 1;
            }
        } else {
            report.benign += 1;
            if detected {
                report.false_positive += 1;
            } else {
                report.true_negative += 1;
            }
        }
    }

    Ok(report)
}

fn collect_files(dir: &Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, files)?;
        } else if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext == "sh")
        {
            files.push(path);
        }
    }
    Ok(())
}

fn expected_label(root: &Path, path: &Path) -> Option<bool> {
    let relative = path.strip_prefix(root).ok()?;
    let first = relative.components().next()?.as_os_str().to_string_lossy();
    match first.as_ref() {
        "malicious" | "mutations" => Some(true),
        "benign" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_empty_report() {
        let report = BenchReport::default();
        let rendered = report.render();
        assert!(rendered.contains("Total cases: 0"));
    }
}
