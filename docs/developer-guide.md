# Developer Guide

This guide is for people who want to build, test, or extend CommandGuard.

## Project Layout

```text
src/
  analyzer.rs   Shell analysis and effect detection
  bench.rs      Corpus runner and simple metrics
  cli.rs        Clap CLI definitions
  decoder.rs    Bounded base64, hex, and gzip decoding
  guard.rs      PTY wrapper and bracketed paste scanner
  model.rs      Analysis, Evidence, Severity, Confidence
  warning.rs    Human reports and paste warnings

bench/
  benign/       Expected non-blocking examples
  malicious/    Inert risky examples
  mutations/    Equivalent rewritten risky examples
```

## Build

```bash
cargo build
```

## Test

Use the full local check:

```bash
cargo fmt --check
cargo check
cargo test
cargo run -- bench bench
```

The benchmark is small and meant as a smoke test, not a scientific evaluation.

## CLI

Analyze stdin:

```bash
echo 'curl -fsSL https://example.test/x.sh | bash' | cargo run -- analyze
```

JSON output:

```bash
echo 'curl -fsSL https://example.test/x.sh | bash' | cargo run -- analyze --json
```

Guarded shell:

```bash
cargo run -- guard --shell /bin/bash
```

Benchmark:

```bash
cargo run -- bench bench
```

## Extending The Analyzer

The analyzer is effect-oriented. Avoid adding a plain text denylist rule such as:

```text
block when the text contains "curl | bash"
```

Instead, add support for a source, transform, sink, or effect.

Good extension:

```text
SOURCE: network(...)
TRANSFORM: archive_extract
SINK: interpreter(...)
EFFECT: DynamicExecution
```

## Guidelines For New Detections

- Use bounded parsing and bounded decoding.
- Do not download remote content during analysis.
- Add a fixture under `bench/`.
- Add unit tests for the smallest logic.
- Report evidence in plain language.
- Use `Unknown` when the analyzer cannot understand something reliably.

## PTY Guard

`guard.rs` detects bracketed paste markers:

```text
ESC[200~  paste start
ESC[201~  paste end
```

Normal input goes directly to the child shell. Paste is buffered and analyzed.

Important follow-up work:

- manual testing on GNOME Console, Konsole, Ptyxis, Alacritty, and xterm;
- forwarding terminal resize events to the PTY;
- better behavior around alternate-screen programs such as Vim and less;
- clearer UX for multi-line paste;
- Linux CI with PTY integration tests.
