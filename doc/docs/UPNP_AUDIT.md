Note all of this i write what i know from proof and notice UNKNOW for what i don't know


# UPNP_AUDIT.md — UPnP weapon contract audit

## Status: AUDIT IN PROGRESS — do not implement until complete

This file answers the contract audit requested before any
`upnp.c`, `upnp_http.c`, or `upnp_xml.c` implementation begins.

It follows the discipline established in `docs/RESEARCH.md`,
`docs/PROBING_DESIGN.md`, and `docs/AI_CONTEXT.md`:

- **Known fact** → kept
- **Documented rule** → kept
- **Test evidence** → kept
- **Historical reason** → searched for
- **AI assumption** → marked as assumption
- **Unknown** → left as UNKNOWN, not filled by imagination

Nothing in this file is a decision. It is a preparation for a
decision that Sing will make.

---

## Context

`weapons/internal/upnp.h` and `weapons/upnp.c` exist in the repo as
empty placeholders (1 byte each). They are not implementations.
This audit determines what they must contain, and what supporting
helpers (`upnp_http.*`, `upnp_xml.*`) are required, before any code
is written.

---

## Question A — What must `upnp.c` actually do?

### A.1 Protocol purpose

UPnP IGD (Internet Gateway Device) allows a host to ask its local
gateway to create a port mapping (port forwarding) from the
gateway's public IP to the host's private IP. For Xury, this is a
"router mapping" weapon: it does not require peer cooperation and
does not consume bandwidth through a peer.

### A.2 Required protocol steps

Based on the UPnP Device Architecture specification, a complete
AddPortMapping flow is:

```
1. SSDP discovery (UDP multicast)
   → find IGD device
   → receive LOCATION URL (device description URL)

2. HTTP GET the LOCATION URL
   → receive device description XML

3. Parse device description XML
   → find WANIPConnection or WANPPPConnection service
   → extract controlURL and serviceType

4. SOAP POST to controlURL
   → AddPortMapping action with our desired external port,
     internal port, internal IP, protocol (UDP), lease duration

5. Parse SOAP response XML
   → confirm success or extract error code
```

### A.3 What this means for `xury_weapon_upnp_try()`

The function must:

1. Validate `ctx` and `out` (NULL → `XURY_ERR_INVAL`)
2. Validate `ctx->peer` is usable (family, non-empty ip, non-zero port)
3. Fast-path applicability rejection if
   `ctx->applicability_ctx.upnp_available == false`
   → `XURY_OK`, `success = false`, `elapsed_ms = 0`
4. Perform the 5-step protocol flow above
5. On success: `success = true`, `established_peer` = the resulting
   public endpoint (gateway's public IP + mapped external port), or
   `ctx->peer` — TBD, see A.4
6. On failure: `XURY_OK`, `success = false`, `elapsed_ms` recorded
7. On platform error (socket creation, etc.): propagate the error

### A.4 UNKNOWN — what should `established_peer` contain on success?

For `ipv6.c`, `established_peer = ctx->peer` because the peer is
the target. For UPnP, the result of AddPortMapping is not a peer
connection — it is a port mapping. There is no established peer.

Options (not yet decided):

- **Option A** — `established_peer = ctx->peer` (echo, matching ipv6.c)
- **Option B** — `established_peer` = our own public endpoint
  (gateway public IP + external port), which is what we learned
- **Option C** — `established_peer` is zeroed, and `success = true`
  only signals "mapping created"

This is an **architecture question** because it affects what
`blitz/race.c` can do with the result. Marked UNKNOWN until Sing
decides.

---

## Question B — What exact HTTP features are required?

### B.1 HTTP methods

Based on UPnP IGD flow:

- **GET** — to fetch the device description from the LOCATION URL
- **POST** — to send the SOAP AddPortMapping action

No other methods are required.

### B.2 HTTP version

UPnP Device Architecture 1.0 requires HTTP/1.1 for control requests.
HTTP/1.0 responses are accepted but not required to send.

**Assumption (marked as such):** Xury only needs to *send* HTTP/1.1
and *parse* HTTP/1.1 responses. It does not need HTTP/2 or HTTP/3.

### B.3 Required HTTP features

| Feature | Required? | Reason |
|---|---|---|
| Request line (method, path, version) | YES | GET and POST both need it |
| `Host:` header | YES | HTTP/1.1 requires it |
| `Content-Length:` header (request) | YES | SOAP POST has a body |
| `Content-Type:` header | YES | `text/xml; charset="utf-8"` for SOAP |
| `SOAPACTION:` header | YES | Required for SOAP 1.1 |
| `Connection: close` | LIKELY | Simpler than keep-alive |
| Response status line parsing | YES | Need 200 OK |
| Response header parsing | YES | Need `Content-Length` |
| Response body reading | YES | SOAP response |
| Chunked transfer-encoding | **UNKNOWN** | Some routers may send it |
| Redirects (3xx) | **UNKNOWN** | Some routers may redirect |
| Keep-alive | LIKELY NOT | Close after each request is simpler |
| TLS / HTTPS | NO | UPnP IGD is HTTP only |

### B.4 UNKNOWN — chunked encoding

Some routers send `Transfer-Encoding: chunked` responses. Handling
chunked encoding adds significant complexity. **Whether Xury must
support it is UNKNOWN.** It may be sufficient to fail honestly on
chunked responses and document the limitation.

### B.5 UNKNOWN — redirects

Some routers redirect GET requests. Whether Xury must follow
redirects is UNKNOWN. It may be sufficient to fail honestly.

---

## Question C — What exact XML features are required?

### C.1 XML uses in UPnP IGD

Two XML documents must be handled:

**C.1.1 Device description XML (received)**
- Structure: nested elements with attributes
- What we need: extract text content of specific elements
  (`controlURL`, `serviceType`, `URLBase`)
- What we do NOT need: attributes on nested elements, namespaces
  fully resolved, DTDs, entities

**C.1.2 SOAP request XML (sent)**
- Structure: envelope/body/action/arguments
- What we need: emit a fixed template with a few substituted values

**C.1.3 SOAP response XML (received)**
- Structure: envelope/body/actionResponse
- What we need: detect success or extract error code

### C.2 Required XML features

| Feature | Required? | Reason |
|---|---|---|
| Element name matching | YES | Find `<controlURL>` etc. |
| Text content extraction | YES | Read between `>...<` |
| Nesting / depth | YES | `<root><service><controlURL>` |
| Attributes | MAYBE | Device description uses some |
| Namespaces | MAYBE | `<u:controlURL>` vs `<controlURL>` |
| XML declaration (`<?xml?>`) | YES | Skip it |
| Comments (`<!-- -->`) | MAYBE | Skip them |
| CDATA (`<![CDATA[]]>`) | MAYBE | Skip them |
| Character entities (`&lt;`) | MAYBE | Decode them |
| DTDs | NO | Not used in UPnP IGD |
| XPath | NO | Overkill for this use case |

### C.3 UNKNOWN — full parser vs minimal string matching

Two implementation strategies:

**Strategy 1 — Full parser**
- Build a DOM-like tree
- Handle all XML features correctly
- 500–800 lines
- Requires memory allocation

**Strategy 2 — Minimal string matching**
- Search for `<tag>` and `</tag>` in the raw bytes
- Extract text between them
- Ignore comments, CDATA, entities (or handle them minimally)
- 200–400 lines
- No allocation (stack buffers only)
- Matches `probing.c`'s philosophy

**This is an architecture/implementation decision** that Sing must
make. The trade-off is robustness vs. simplicity.

---

## Question D — Which existing Xury APIs can provide the needed primitives?

### D.1 Socket primitives

From `platform/platform.h` (confirmed):

| Need | Function | Notes |
|---|---|---|
| Create TCP socket | `xury_platform_sock_create(XURY_AF_INET, XURY_PLATFORM_SOCK_TCP, &s)` | UPnP IGD is IPv4 only |
| Create UDP socket (SSDP) | `xury_platform_sock_create(XURY_AF_INET, XURY_PLATFORM_SOCK_UDP, &s)` | For SSDP multicast |
| TCP connect | `xury_platform_sock_connect(s, &ep)` | For HTTP |
| UDP sendto | `xury_platform_sock_sendto(s, buf, len, &ep, &sent)` | For SSDP |
| UDP recvfrom | `xury_platform_sock_recvfrom(s, buf, cap, &from, &len, timeout_ms)` | For SSDP response |
| TCP send | `xury_platform_sock_sendto` OR a TCP-specific send | **UNKNOWN** — `platform.h` only declares `sendto`; TCP send may reuse it (with `to = NULL`)? |
| TCP recv | `xury_platform_sock_recvfrom` OR a TCP-specific recv | **UNKNOWN** — same concern |
| Wait readable | `xury_platform_sock_wait_readable(s, timeout_ms)` | For HTTP response |
| Close | `xury_platform_sock_close(s)` | Cleanup |

**D.1.1 UNKNOWN — TCP send/recv in platform layer**

`platform.h` declares only `sendto` and `recvfrom`. For TCP, the
connected socket cannot use `sendto` with a peer address, and
`recvfrom` requires a source address. Either:

- The platform layer accepts `sendto(s, buf, len, NULL, &sent)` for
  connected TCP (likely, but unconfirmed)
- There is a separate `send`/`recv` pair not seen yet
- The core layer provides `xury_sock_send`/`xury_sock_recv` wrappers

**This must be confirmed before HTTP can be written.** If no TCP
send/recv path exists, it must be added to the platform layer (a
dependency-first addition), not faked.

### D.2 Bytes primitives

From `core/internal/bytes.h` (confirmed):

- `xury_cursor_t` — buffer + length + offset
- `xury_cursor_init`, `xury_cursor_init_read`
- `xury_bytes_get`, `xury_bytes_get_slice`, `xury_bytes_skip`
- `xury_bytes_put`, `xury_bytes_put_zero`
- `xury_bytes_get_be16/32/64`, `xury_bytes_put_be16/32/64`
- `xury_bytes_get_le16/32/64`, `xury_bytes_put_le16/32/64`

**Gap:** No string helpers (search for substring, case-insensitive
compare, split by delimiter). HTTP header parsing and XML tag
matching will need these. They do not currently exist in Xury.

**Implication:** `upnp_http.c` and `upnp_xml.c` will need their own
string matching helpers, OR `core/internal/str.h` must be added as
a new dependency. See Question E.

### D.3 Memory primitives

From `core/internal/mem.h` (referenced in `core/` directory
listing; not yet read in full):

**Assumption:** Xury has `xury_mem_alloc`, `xury_mem_free`,
`xury_mem_zero`, `xury_mem_copy`, `xury_mem_move`, `xury_mem_compare`.
The exact names are UNKNOWN.

**For UPnP:** If the minimal XML strategy is chosen, no allocation
is needed. If the full parser is chosen, allocation is required.

### D.4 Time primitives

From `core/internal/time.h` (confirmed):

- `xury_time_now_ms()`, `xury_time_now_us()`
- `xury_time_elapsed_ms(start)`
- `xury_time_deadline_in(timeout_ms)`, `xury_time_deadline_passed`, `xury_time_deadline_remaining_ms`
- `xury_time_sleep_ms(ms)`

These are sufficient for HTTP timeouts and deadline tracking.

### D.5 Logging primitives

From `core/internal/log.h` (not read; assumed):

**Assumption:** Xury has `xury_log_*` macros for levels TRACE,
DEBUG, INFO, WARN, ERROR. Exact names UNKNOWN.

`ipv6.c` does not log anything — it only returns error codes. It
may be that the weapon layer does not log directly, and only the
host hook receives log events.

**UNKNOWN** — whether `upnp.c` should log, and with what macros.

---

## Question E — What data structures belong in each header?

### E.1 `weapons/internal/upnp.h`

Declares:
- `xury_weapon_upnp_try(const xury_weapon_attempt_ctx_t *ctx, xury_weapon_attempt_result_t *out)`

Follows the exact pattern of `weapon_ops.h`. No new structs unless
UPnP needs state beyond the attempt context.

**UNKNOWN — does UPnP need extra state?**

For `ipv6.c`, the attempt context was enough. For UPnP, the flow
has multiple steps, but each step's state is local to the function.
No extra public struct seems needed.

**Tentative:** `upnp.h` contains only the function declaration and
a documentation comment. No structs.

### E.2 `weapons/internal/upnp_http.h`

Declares:
- A minimal HTTP request function (GET)
- A minimal HTTP request function (POST)
- A response struct or out-params (status code, body, body length)
- No global state

**Tentative struct:**

```c
typedef struct {
    int      status_code;    /* 200, 404, 500, ... */
    uint8_t *body;           /* caller-supplied buffer */
    size_t   body_len;       /* bytes actually written */
    bool     body_truncated; /* if body was larger than buffer */
} xury_upnp_http_response_t;
```

**UNKNOWN — should HTTP live in `upnp_http.h` or be a broader
`http.h`?** Decision made: `upnp_http.h` (UPnP-local), per ChatGPT's
architecture decision. But the function names inside still need to
be decided: `xury_upnp_http_get`? `xury_http_get`? The prefix
matters for future renaming if HTTP ever moves to core.

### E.3 `weapons/internal/upnp_xml.h`

Declares:
- A function to extract text content of a named element
- A function to find a nested element by path
- No global state

**Tentative struct:**

```c
typedef struct {
    const char *start;  /* pointer into the buffer */
    size_t      len;    /* length of the text */
} xury_upnp_xml_text_t;
```

**Tentative functions:**

```c
xury_err_t xury_upnp_xml_find(const uint8_t *buf, size_t len,
                              const char *path,
                              xury_upnp_xml_text_t *out);
```

Where `path` might be `"root/device/serviceList/service/controlURL"`
or similar. Whether path syntax uses `/` or some other separator
is **UNKNOWN** — depends on how much complexity the minimal parser
needs.

---

## Question F — What is explicitly OUT OF SCOPE?

### F.1 Out of scope for `upnp.c`

- **NAT-PMP** — separate weapon (next in locked order)
- **PCP** — separate weapon
- **SSDP advertisement** (sending NOTIFY) — we only search
- **UPnP eventing (GENA)** — not needed for AddPortMapping
- **UPnP AV / MediaServer / etc.** — only IGD
- **IPv6 UPnP** — IGD:1 is IPv4 only; IGD:2 adds IPv6 but is
  out of scope for the first implementation
- **HTTPS / TLS** — UPnP control is HTTP only
- **Persistent mappings across process restarts** — the mapping is
  created and (presumably) released; persistence is the host's job
- **Removing stale mappings from previous runs** — out of scope;
  each try creates a fresh mapping

### F.2 Out of scope for `upnp_http.c`

- **HTTP/2, HTTP/3** — HTTP/1.1 only
- **TLS** — plain HTTP
- **Chunked transfer-encoding** — pending decision (see B.4)
- **Redirects** — pending decision (see B.5)
- **Cookies** — not used by UPnP IGD
- **Authentication** — not used by UPnP IGD (unauthenticated SOAP)
- **Connection pooling / keep-alive** — one request per connection
- **Compression (gzip/deflate)** — not used by UPnP IGD

### F.3 Out of scope for `upnp_xml.c`

- **Full XML 1.0 / 1.1 compliance** — minimal subset only
- **DTD validation** — no DTDs in UPnP IGD
- **XML Schema validation** — no schemas in UPnP IGD
- **XPath** — overkill; path is simple
- **XML namespaces (full resolution)** — handled superficially at best
- **XML writing beyond a fixed SOAP template** — no generic writer

### F.4 Out of scope for the weapon layer overall

- **Any hardcoded server address** (per `docs/PROBING_DESIGN.md`)
- **Any third-party UPnP library** (libupnp, miniupnpc, etc.) — Xury
  implements its own, or does not implement it
- **Any external XML library** (libxml2, expat, etc.) — same rule

---

## Question G — What tests can be written without fake/mock protocol behavior?

This is the hardest question. Xury's discipline (per
`tests/unit/scan/test_probing.c` header comment) is: **"No mocks.
The platform layer is the real one."**

For UPnP, that means:

### G.1 What CAN be tested without a real router

| Test | What it verifies | Real or fake? |
|---|---|---|
| Null argument validation | `XURY_ERR_INVAL` on NULL ctx/out | Real, no network |
| Bad peer family | `XURY_ERR_INVAL` | Real, no network |
| Fast-path rejection | `upnp_available == false` → `success = false`, `elapsed_ms = 0` | Real, no network |
| XML parser — well-formed input | Correct extraction of known XML | Real parser, real XML text (from spec examples) |
| XML parser — malformed input | Honest `XURY_ERR_BAD_ENDPOINT` or similar | Real parser, bad XML text |
| HTTP request builder | Bytes produced match expected HTTP/1.1 format | Real builder, string comparison |
| HTTP response parser | Correct extraction from a known response | Real parser, real HTTP response text |

### G.2 What CANNOT be tested without a real router

| Test | Why |
|---|---|
| SSDP discovery | Requires a real UPnP-capable gateway on the LAN |
| Full AddPortMapping flow | Requires a real router that responds |
| End-to-end with real port mapping | Requires external verification |

### G.3 UNKNOWN — where do real UPnP test fixtures come from?

The XML and HTTP test inputs must be **real captures** from real
routers, not invented by the AI or the developer. Possible sources:

- Capture from a real router in a lab
- Published examples in the UPnP specification
- Public captures from open-source UPnP projects (carefully
  attributed)

**The rule:** no fixture may be invented to make a test pass. If a
fixture is needed, it must be traceable to a real source.

**UNKNOWN — do we have access to a real UPnP router for capture?**

This is a question for Sing.

### G.4 What this means for the implementation

The UPnP weapon will have:
- **Unit tests** that use real XML/HTTP text (from real captures or
  spec examples) as input to the parser, without any network
- **Integration tests** (Phase P) that exercise the full flow against
  a real router, likely in `tests/integration/test_real_network.c`
  (already scoped in the repo tree)
- **No mocks** at any level

---

## Summary of UNKNOWNs requiring Sing's decision

| # | Unknown | Blocks |
|---|---|---|
| 1 | `established_peer` semantics on UPnP success (A.4) | `upnp.c` contract |
| 2 | Chunked encoding support (B.4) | `upnp_http.c` |
| 3 | Redirect support (B.5) | `upnp_http.c` |
| 4 | Full XML parser vs minimal string-matching (C.3) | `upnp_xml.c` |
| 5 | TCP send/recv in platform layer (D.1.1) | HTTP transport |
| 6 | String helpers in core, or UPnP-local (D.2) | `upnp_http.c` + `upnp_xml.c` |
| 7 | Logging: does weapon layer log? (D.5) | `upnp.c` style |
| 8 | Prefix for HTTP functions: `xury_upnp_http_*` vs `xury_http_*` (E.2) | Renaming cost if ever moved |
| 9 | Path syntax for XML element search (E.3) | `upnp_xml.c` API |
| 10 | Real UPnP fixture source (G.3) | Test plan |
| 11 | IGD version support: IGD:1 only, or IGD:2 also? (A.2) | Scope |

---

## What this audit does NOT decide

- Whether to implement `upnp.c` now, later, or not at all
- Whether to defer UPnP in favor of NATPMP
- How much time or effort any option requires

Those are Sing's decisions, informed by this audit.

---

## Next step

Sing reviews this audit. For each UNKNOWN, Sing either:
- provides an answer, or
- marks it as "not yet decided — investigate further", or
- marks it as "out of scope for the first implementation"

Once all blocking UNKNOWNs are resolved, implementation can begin
with `weapons/internal/upnp.h` (populated from an empty placeholder),
then `upnp_http.h` and `upnp_xml.h`, then the `.c` files.

**No code is written until this audit is resolved.**

---

*End of UPNP_AUDIT.md*
```

  
