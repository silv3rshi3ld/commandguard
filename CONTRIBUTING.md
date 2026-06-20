# Contributing To CommandGuard

Thanks for helping make Linux terminal paste safer.

CommandGuard is early, so the most useful contributions are focused and testable:

- safe benchmark fixtures under `bench/`;
- analyzer improvements with evidence and tests;
- Linux terminal compatibility notes;
- beginner-friendly documentation;
- bug reports with exact commands and expected behavior.

## Local Checks

Run these before opening a pull request:

```bash
cargo fmt --check
cargo check
cargo test
cargo run -- bench bench
```

## Safe Fixture Rules

Benchmark fixtures must be inert:

- use `example.test`, localhost, or local sinkholes;
- do not include live malware;
- do not include real credentials;
- do not include working command-and-control endpoints;
- keep payloads short and demonstrative.

## Detection Philosophy

Prefer semantic effects over text matching.

Good:

```text
network source -> decoder -> interpreter
```

Weak:

```text
block whenever command contains "curl | bash"
```

The goal is to explain what a pasted command does, not just match scary strings.

## Pull Request Checklist

- The change is scoped to one behavior or documentation improvement.
- New analyzer behavior has unit tests or bench fixtures.
- Warning text is understandable to a non-expert Linux user.
- No live malicious infrastructure, credentials, or operational malware are included.
