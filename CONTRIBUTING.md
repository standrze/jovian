# contributing

Use Swift 6.4 or later on macOS 13 or later. Read the
[Swift project style guide](Documentation/SwiftProjectStyle.md) before changing
source layout or public APIs.

Run commands from `jovian/`; it has its own manifest and build directory:

```sh
scripts/check-format.sh
swift test
swift build --product jovian
swift run jovian --help
python3 scripts/smoke.py .build/debug/jovian
```

Use `scripts/format.sh` to format this package. Avoid reformatting unrelated code.
Do not run concurrent SwiftPM builds against the same build directory.

Tests belong in `Tests/JovianTests/` for library behavior and
`Tests/JovianCLITests/` for command parsing and CLI behavior. Cover meaningful
protocol, logging, and certificate contracts with local fixtures. Network tests
may require permission to bind loopback sockets in a sandbox.

Keep public APIs documented and reusable. The CLI owns process arguments and
startup policy; the library owns proxy behavior. Do not add a dependency on the
parent application or browser merely because these projects share a checkout.

Report formatting, unit tests, networking checks, and platform coverage
separately. macOS requirements in the manifest do not establish Linux support.

The consolidated wire regressions are deterministic local fixtures by default:

```sh
python3 scripts/routing-smoke.py
python3 scripts/mocking-smoke.py
python3 scripts/martian-completion-smoke.py
python3 scripts/headers-shaping-smoke.py
python3 scripts/proxy-upgrades-smoke.py
python3 scripts/upstream-proxies-smoke.py
```

`--live` on routing, completion, shaping, and upstream-proxies additionally
checks public HTTPS certificate verification and nested TLS against example.com.
Keep these optional outbound checks separate from local validation.
