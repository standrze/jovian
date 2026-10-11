# swift project style

This guide adapts the shared Swift project conventions for swift-jovian. Explicit
user instructions and established local conventions take precedence. Do not
reformat unrelated code.

## formatting

- Four spaces, no tabs, UTF-8, LF, and a final newline.
- Use a 120-column code target and wrap earlier when it improves readability.
- One statement per line. Expand initializers and control flow rather than
  combining statements with semicolons.
- Separate related steps with a blank line; do not add blank lines immediately
  inside braces.
- Use the toolchain's `swift format` with this package's `.swift-format`.
  Preserve protocol bytes, fixtures, and literal text during formatting changes.

## package boundaries

Use standard SwiftPM discovery and keep the package independently buildable:

```text
Package.swift
Sources/
    Jovian/
    JovianCLI/
Tests/
    JovianTests/
    JovianCLITests/
Documentation/
scripts/
```

The library product and module are `Jovian`; the executable product is `jovian`
and its target is `JovianCLI`. The GitHub repository is `jovian`; the Swift package identity is `swift-jovian`.

`JovianCLI` owns process arguments, startup, and user-facing command behavior.
`Jovian` owns reusable proxy behavior, traffic records, and certificate inspection.
The library must not import the CLI. Neither target depends on ono-sendai or
lowlight. Co-location does not create a runtime or API dependency.

Keep executable entrypoints short: parse options, construct the application, run
it, and report errors. Keep network behavior and reusable data types in the
library. Add directories and targets only when they express an actual ownership
boundary.

## use maintained packages

Use Apple ArgumentParser for launch options, subcommands, help, and validation.
Use SwiftNIO for event loops, socket transport, channels, and HTTP framing. Use
Swift Logging for diagnostics and Swift Collections where queue or ordered
collection behavior is required. Foundation supplies Codable and common file
operations.

Use `swift-certificates` for explicit X.509 parsing and inspection, `swift-asn1`
for ASN.1 data, and `swift-crypto` for supported cryptographic primitives.
Certificate parsing is distinct from transport encryption and trust validation.
Do not present metadata inspection as a verified trust result.

Declare the products imported by each target explicitly. Add a package for an
actual feature and check toolchain and platform requirements. Avoid unused
dependencies and bespoke replacements for standard package functionality.

## source organization

Name each source file after its primary type or focused responsibility. Small
related types can share a file. Avoid generic `Utils` or `Managers` directories.
Keep related operations near each other, with public state, private storage,
initialization, public behavior, and implementation helpers grouped coherently.

Use `UpperCamelCase` for Swift types and `lowerCamelCase` for members and locals.
Prefer familiar names that explain ownership, units, and purpose. Use `let` by
default, keep mutation local, and expose only APIs callers need. Preserve public
signatures during readability-only changes.

Give state changes their own lines. Name intermediate values when doing so makes
units or transitions clear. Avoid nested ternaries and compressed control flow.

## contracts and concurrency

Add concise `///` documentation to public types and operations. Document units,
ownership, side effects, errors, and limits where they affect a caller. Private
comments should explain invariants or decisions rather than restate code.

Confine platform APIs and unsafe pointers to narrow boundaries. Keep HTTP and TLS
responsibilities distinct. Make buffer limits, cancellation, backpressure, event
loop ownership, and shutdown behavior explicit. Do not add unchecked Sendable
conformance without establishing and documenting the synchronization boundary.

Do not introduce tasks, actors, queues, or background threads solely for style.
Preserve event ordering and cleanup paths during refactoring. Keep diagnostic
logging separate from domain traffic records and avoid exposing credentials or
payloads through ordinary diagnostics.

## checks

Run from this package directory:

```sh
scripts/check-format.sh
swift test
swift build --product jovian
```

Use `scripts/format.sh` when formatting is required. Tests mirror library and CLI
ownership and verify behavior rather than filenames or implementation details.
Prefer deterministic local fixtures for network and certificate work.

Do not run simultaneous SwiftPM builds in the same build directory. Before
finishing, inspect for lost files, public API changes, stale links, changed
protocol literals, and unrelated edits. Report formatting, tests, network checks,
and tested platforms separately.
