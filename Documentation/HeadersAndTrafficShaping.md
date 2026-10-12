# Header operations and request correlation

`POST /configure` accepts these canonical Martian nodes, including inside groups,
filters, and `else` branches:

| Node | Fields | Behavior |
|---|---|---|
| `header.Append` | `name`, `value`, optional `scope` | Appends another field value without removing existing values. |
| `header.Blacklist` | `names`, optional `scope` | Removes every value for each named header, case-insensitively. |
| `header.Copy` | `from`, `to`, optional `scope` | Replaces the destination with the first source value. A missing source produces an empty destination value, as in Martian. |
| `header.Id` | Optional `scope` | Sets `X-Martian-ID` to the exchange UUID when its first value is missing or empty; preserves an existing nonempty ID. Request scope only. |

Append, blacklist, and copy default to both request and response scopes. They
operate on the current message at their position in the pipeline; copy does not
copy a request header into a response header. Header names and values are
validated at activation. Host/Content-Length/Transfer-Encoding use Martian special
field semantics; outgoing framing is normalized to actual body bytes. See
[special header fields](ProxyUpgrades.md#special-header-fields).

```json
{
  "fifo.Group": {
    "modifiers": [
      {"header.Id": {}},
      {"header.Append": {"scope": ["request"], "name": "X-Test", "value": "fixture"}},
      {"header.Copy": {"scope": ["request"], "from": "X-Test", "to": "X-Test-Copy"}},
      {"header.Blacklist": {"scope": ["response"], "names": ["X-Powered-By"]}}
    ]
  }
}
```

For request/response correlation, Jovian additionally supports native ID echo:

```json
{"modifier":{"type":"headerID","echoResponse":true}}
```

This adds the request's `X-Martian-ID` to the response, including local synthetic
responses. Each exchange on a keep-alive connection receives its own generated
ID. A supplied ID is preserved and echoed. Request/response HAR headers retain
the same value, so a client response can be matched to its captured exchange.
Canonical `header.Id` retains Martian's request-only behavior.

Other native nodes are `headerAppend` (`scope`, `name`, `value`),
`headerBlacklist` (`scope`, `names`), and `headerCopy` (`scope`, `from`, `to`).
Omitted native scopes default to request and response.

# Traffic shaping

Traffic policy has its own atomic API, separate from modifier/verifier rules:

| Method | Path | Behavior |
|---|---|---|
| `POST` | `/shape-traffic` | Validates and replaces Martian-format traffic policy; echoes the accepted JSON. |
| `GET` | `/shape-traffic` | Jovian extension returning the active traffic policy. |

Bandwidth values in this JSON are **bytes per second**. Latency and halt durations
are **milliseconds**. This follows the pinned source's JSON implementation;
its comments about bit-rate query parameters do not describe this JSON API.

```sh
curl -sS http://127.0.0.1:8181/shape-traffic \
  -H 'Content-Type: application/json' -d '{
  "trafficshape": {
    "default": {
      "bandwidth": {"up": 65536, "down": 131072},
      "latency": 100
    },
    "shapes": [{
      "url_regex": "^https?://[^/]+/download",
      "max_global_bandwidth": 65536,
      "throttles": [
        {"bytes": "0-32768", "bandwidth": 16384},
        {"bytes": "32768-", "bandwidth": 32768}
      ],
      "halts": [{"byte": 16384, "duration": 250, "count": 1}],
      "close_connections": [{"byte": 131072, "count": 1}]
    }]
  }
}'
```

`default.bandwidth.up` caps aggregate client-to-proxy traffic and `down` caps
aggregate proxy-to-client traffic across connections. Default budgets include
HTTP headers and framing. Latency applies once before the first read and once
before the first write for a connection, rather than once per message. Defaults
also apply to opaque CONNECT tunnel bytes and upgraded streams. Intercepted HTTPS
uses a shaped plaintext stream after TLS negotiation.

Absent/zero default bandwidth and absent/zero `max_global_bandwidth` use Martian's
500 Gbit/s equivalent, 62,500,000,000 bytes/s, treated as unlimited by Jovian's pacer.
An omitted default/shape list is empty. Clear shaping with:

```sh
curl -sS http://127.0.0.1:8181/shape-traffic \
  -H 'Content-Type: application/json' -d '{"trafficshape":{}}'
```

This preserves modifier rules and verifier state. Conversely, `/configure` does
not clear traffic policy. Legacy CLI/native upload/download limits remain
additional limits when configured; leave them unset when using this API alone.

## URL policies and actions

The first declared matching `url_regex` selects a response policy. Matching uses
the final URL after request modifiers. Intercepted targets retain their CONNECT
authority, which commonly includes `:443`; account for that in regexes.

URL policy offsets count decoded response payload bytes, excluding HTTP headers,
chunk lines, and trailers. Chunked framing, extensions, and trailers are retained
on the wire. Fixed-length, chunked, streamed, synthetic, and intercepted HTTPS
response bodies use the same payload-offset rules.

- `throttles` set a per-transfer rate within non-overlapping, half-open intervals:
  `0-100` covers offsets 0 through 99, `100-` continues to EOF, and `-100` starts
  at zero. Outside intervals, the transfer uses its shape's maximum bandwidth.
- `max_global_bandwidth` caps aggregate payload throughput for the selected
  shape across simultaneous transfers. Default transport caps also apply.
- `halts` pause at `byte` for `duration` milliseconds and then resume.
- `close_connections` close the downstream connection at `byte`, producing a
  truncated transfer. Jovian does not append a synthetic 502 to an already-started
  response. Captures retain the actual HTTP status, payload bytes sent, request
  and response headers, and a traffic-shaping error.
- Action `count` is shared across transfers in that policy: a positive count is
  consumed atomically; `-1` repeats indefinitely. Actions beyond EOF are not
  consumed. Halts precede closes at the same offset. An action at zero runs before
  the first payload byte; bodyless responses do not consume payload actions.

For a valid single-part 206 response, offsets begin at the absolute resource
position in `Content-Range`, allowing a resumed transfer to hit an action later
in the file. Invalid or multipart 206 ranges use only default transport shaping.
URL payload policies do not inspect opaque CONNECT or upgraded stream contents.

## Validation and replacement

Malformed JSON, invalid regexes, negative bandwidth, overlapping/reversed/empty
intervals, invalid action counts, or unsupported types leave the old policy
active, including its remaining action counts. Halts/latency are bounded to
60,000 ms; at most 256 shapes and 2,048 halt/close actions per shape are accepted.
Patterns are limited to 4,096 bytes and each ICU match has a 50 ms budget.

Each response keeps the URL policy selected before its headers are written.
Replacing policy creates fresh shared counters and bandwidth budgets for later
responses. In-flight URL actions finish on their original policy; default
transport budgets refresh on subsequent I/O operations. Proxy shutdown wakes
pending pacing, latency, and halt waits.

Jovian implements the canonical JSON schema and actions, but does not claim exact
Martian timing/parity: it uses strict pacing rather than one-second burst buckets,
deterministic first-match ordering rather than Go map iteration, ICU rather than
RE2, payload offsets independent of chunk framing, and explicit response policy
snapshots rather than invalidating actions on old connections during replacement.
It also honors `up` as upload and `down` as download; the pinned handler's bucket
assignment reverses those labels. These differences are intentional and tested.

## Checks

```sh
swift test
swift build --product jovian
python3 scripts/headers-shaping-smoke.py
python3 scripts/headers-shaping-smoke.py --live
python3 scripts/mocking-smoke.py
python3 scripts/routing-smoke.py --live
```

The new smoke uses temporary loopback fixtures for correlation, exact truncation,
range/chunk offsets, halt counts, concurrent global limits, default rates,
keep-alive latency, policy reset, static mocks, and opaque CONNECT. `--live` adds
a truncated intercepted HTTPS transfer against example.com with normal macOS
origin trust validation. Test CA files remain temporary and are not installed.
