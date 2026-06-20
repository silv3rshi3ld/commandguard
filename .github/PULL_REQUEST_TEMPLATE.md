## Summary

What changed?

## Type

- [ ] Analyzer behavior
- [ ] PTY guard behavior
- [ ] Benchmark fixture
- [ ] Documentation
- [ ] Maintenance

## Safety

- [ ] No live malware
- [ ] No real credentials
- [ ] No working command-and-control endpoints
- [ ] Fixtures use inert payloads or reserved domains

## Verification

```bash
cargo fmt --check
cargo check
cargo test
cargo run -- bench bench
```
