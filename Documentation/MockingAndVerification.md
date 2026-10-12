# Local mocks and composable verification

These rules work for HTTP and intercepted HTTPS. Opaque CONNECT tunnels do not
expose HTTP messages to modifiers. Jovian accepts both the canonical Martian
envelopes below and native rules through `POST /configure` on the admin listener.
Invalid configuration leaves the active rules and verification state unchanged.

## Serve local files

Create a directory containing test fixtures, then configure its absolute path:

```sh
mkdir -p /tmp/jovian-fixtures
printf '{"healthy":true}\n' > /tmp/jovian-fixtures/health.json
curl -sS http://127.0.0.1:8181/configure -H 'Content-Type: application/json' -d '{
  "url.Filter": {
    "host": "api.example.test",
    "modifier": {
      "static.Modifier": {
        "rootPath": "/tmp/jovian-fixtures",
        "explicitPaths": {"/health": "health.json"}
      }
    }
  }
}'
curl -sS --noproxy '' -x http://127.0.0.1:8080 http://api.example.test/health
```

The request scope marks the exchange to skip its origin round trip. The response
scope reads the file for the final rewritten URL. Both scopes are enabled by
default. With response scope alone the origin is contacted first; with request
scope alone the result is an empty 200 unless another response modifier fills it.
Keep both scopes enabled for a standalone local mock. A session's method/origin
scope is validated before the response modifier reads any file.

`explicitPaths` maps decoded URL paths to root-relative file names. Otherwise the
decoded URL path names a file beneath the root. Query strings do not affect file
selection. Repeated slashes are collapsed; dot components, control characters,
backslashes, absolute mapped file names, and symlinks beneath the root are
rejected. Descriptor-relative opens prevent a directory replacement from escaping
the root. The root directory is opened at activation and retained by in-flight
exchanges when configuration changes.

Only regular files are served. Files above 4 MiB stream in bounded descriptor
reads; HEAD sends metadata without reading content. Single, suffix, open-ended,
and multipart ranges are supported with a 16-range cap. Malformed or wholly
unsatisfiable ranges receive 416. Missing files receive 404, forbidden paths/file
types receive 403, and unsupported methods receive 405. There is no origin
fallback, directory listing, or conditional caching. See [range and streaming
semantics](ProxyUpgrades.md#replacement-ranges-and-streamed-files).

## Build a response without an origin

`skip.RoundTrip` supplies an empty 200 response and allows normal response
modifiers to populate it. It has request scope only:

```json
{
  "fifo.Group": {
    "modifiers": [
      {"skip.RoundTrip": {}},
      {"status.Modifier": {"statusCode": 201}},
      {"body.Modifier": {
        "scope": ["response"],
        "body": "aGVsbG8=",
        "contentType": "text/plain"
      }}
    ]
  }
}
```

The canonical body is base64 (`hello` here). `noop.Modifier` is also accepted for
an explicitly empty branch. Synthetic responses respect HEAD, 204, 205 and 304
body restrictions. They remove conflicting transfer framing and close the client
connection if a streaming upload still has unread bytes.

## Observe requests and responses

Verifiers inspect a message at their position in the ordered modifier tree.
They record failures and allow forwarding to continue. Place a verifier after a
modifier to check its output. Filters and `else` branches can select which
messages reach each verifier.

| Canonical node | Fields | Supported scope and matching |
|---|---|---|
| `header.Verifier` | `name`, optional `value` | Request/response; case-insensitive name, any duplicate value; omitted/empty value tests presence. |
| `method.Verifier` | `method` | Request; case-sensitive exact HTTP method token. |
| `status.Verifier` | `statusCode` | Response; exact status from 100 through 599. |
| `url.Verifier` | Optional `scheme`, `host`, `path`, `query` | Request; nonempty fields must all match; decoded path and raw encoded query. Host uses the same case-insensitive whole-label wildcards as Jovian's URL filter. |
| `querystring.Verifier` | `name`, optional `value` | Request; decoded query and buffered URL-encoded POST/PUT/PATCH form values; repeated values are checked individually. Omitted/empty value tests presence. |
| `failure.Verifier` | Optional `message` | Request; records a failure every time it is reached. It does not generate an HTTP error response. |
| `pingback.Verifier` | Optional `scheme`, `host`, `path`, `query` | Request; begins failed, passes after the first matching request reaches it, stays passed until reset. Nonempty fields match exactly; no host wildcard. |

Omitting `scope` enables the supported directions. Unsupported scopes fail
activation. A pingback in an unreached branch remains pending even when no traffic
has arrived. Admin-listener requests are outside the modifier pipeline and do not
satisfy pingbacks.

```json
{
  "fifo.Group": {
    "modifiers": [
      {"pingback.Verifier": {"host": "api.example.test", "path": "/health"}},
      {"url.Filter": {
        "host": "api.example.test",
        "modifier": {"status.Verifier": {"statusCode": 200}}
      }}
    ]
  }
}
```

```sh
curl -sS http://127.0.0.1:8181/verify
curl -sS -X POST http://127.0.0.1:8181/verify/reset
```

`GET /verify` returns `{"errors":[...]}` with timestamps and messages. Reset clears
observed failures and re-arms all pingbacks; a pending pingback immediately appears
again. Configuration replacement creates a fresh store. In-flight exchanges keep
their original tree, and detached verifiers cannot write into its replacement.
This applies to the new composable rules; legacy host-scoped rules still check
completed traffic log entries.

Observed failures are capped at 10,000 per active composable tree, with an
additional omission notice. Pending pingbacks are listed separately. Messages are
bounded to 2,048 characters and omit request URLs, expected values, and observed
values. A configured `failure.Verifier` message is returned as supplied. Query
form decoding treats `+` as space; malformed encoding or an unavailable streaming
form body records a failure. Special header fields use Martian presence semantics;
exact Martian error strings are not reproduced.

## Native Jovian representation

Use these nodes inside the native document's `modifier` field:

```json
{
  "modifier": {
    "type": "group",
    "modifiers": [
      {"type": "staticFiles", "rootPath": "/tmp/jovian-fixtures", "explicitPaths": {"/health": "health.json"}},
      {"type": "verify", "expectation": {"kind": "pingback", "path": "/health"}},
      {"type": "verify", "scope": ["response"], "expectation": {"kind": "status", "statusCode": 200}}
    ]
  }
}
```

Native verifier `kind` values are `header`, `method`, `status`, `url`, `queryString`,
`failure`, and `pingback`; expectation fields correspond to the canonical table.
`{"type":"skipRoundTrip"}` is the native skip node. Use native `match` rules to
limit mocks or verifiers to selected traffic.

## Validation

```sh
swift test
swift build --product jovian
python3 scripts/mocking-smoke.py
python3 scripts/routing-smoke.py
```

The smoke scripts isolate files, sessions, processes, and loopback origins in
temporary fixtures. Mocking checks include origin bypass, range/HEAD framing,
file-boundary rejection, verifier reset, unread uploads, and session scope.
