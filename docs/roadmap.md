# Roadmap

CommandGuard v0.1 is a prototype. This roadmap describes the next useful milestones.

## v0.1 Stabilization

- Manually test `commandguard guard` on common Linux terminals.
- Forward terminal resize events to the PTY.
- Improve alternate-screen handling for Vim, less, and full-screen TUIs.
- Add more benign Linux documentation fixtures.
- Add more mutation fixtures for quoting, aliases, variables, redirects, and command substitutions.

## v0.2 Shell Coverage

- Improve Bash parsing and normalization.
- Add basic Zsh and Fish support.
- Add package builds for common Linux distributions.
- Add clearer multi-line paste UX.

## v0.3 Research Artifact

- Expand the benchmark corpus.
- Add mutation generators for equivalent command formulations.
- Compare against regex and denylist baselines.
- Document latency, false positives, false negatives, and unsupported syntax.

## Future Ideas

- Browser extension that shares source page context with the terminal tool.
- Optional sandbox inspection mode.
- Native integrations for GNOME Console, Ptyxis, Konsole, and other terminals.
- Human factors study for warning comprehension.
