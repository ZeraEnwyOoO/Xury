# PROBING_DESIGN.md — No-Server Rule

**Xury never uses a server. Not its own, not a third party's, not public
STUN, nothing. Everything is peer-to-peer — Xury talks directly to other
peers and figures things out itself.**

That's the whole rule. No server address is ever hardcoded, shipped, or
defaulted to anywhere in the codebase.

## What this means for F.2 (Probing)

F.2 probes a **peer**, not a server. The caller supplies the peer — Xury
doesn't pick one:

```c
xury_err_t xury_scan_probing(const xury_endpoint_t *peer_targets,
                              size_t peer_count,
                              xury_probing_result_t *out);
```

Where the peer comes from (DHT, bootstrap list, whatever) is not Xury's
job. Xury just probes whatever it's handed.

`peer_count == 0` → `XURY_ERR_INVAL`. Peers don't respond → honest
failure/partial status, same pattern as F.1. Never fabricate a result.

## Open questions before writing probing.c

1. Minimum peer count needed for a meaningful result?
2. Protocol: custom minimal echo (simple, Xury-only) or STUN-compatible
   subset (RFC 5389 §7.3, more interop, more work)?
3. Must every peer run Xury-compatible code, or degrade gracefully against
   non-cooperating endpoints?
4. Timeout / retry strategy per peer?
5. Does TTL discovery need raw-socket permission that may not exist on
   mobile? Fallback to RTT-only if unavailable?

No invented defaults — lock these before implementing.
