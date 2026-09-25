# RESEARCH.md — Xury NAT Port Prediction (Phase F.3)

## Status: PARTIALLY RESOLVED — F.3a/F.3b implemented and tested; F.3c still open research

This file exists because Phase F.3 (Math / Classification / Scoring) contains
logic that **cannot be fully specified from theory alone**. It requires
real-world measurement against real NAT/router devices before the scoring
layer (F.3c) can be trusted in production.

This document exists so that no contributor — human or AI — invents a
threshold, formula, or "NATs usually do X" comment without first checking
here. If you are about to write a magic number into `math.c`, `analysis.c`,
or `classify.c`, stop and read this first.

---

## 1. Why this is a research problem, not an implementation problem

NAT was designed to solve IPv4 address scarcity by letting private networks
share public IPv4 addresses — **not** as a security boundary, and not with
any single standardized port-allocation algorithm.

**RFC 4787** ("NAT Behavioral Requirements for Unicast UDP") formally
describes this: NAT behavior varies along multiple independent dimensions,
including:

- **Mapping behavior**: Endpoint-Independent, Address-Dependent, or
  Address-and-Port-Dependent Mapping
- **Port allocation strategy**: implementations may use port preservation,
  sequential allocation, random allocation, or port overloading — RFC 4787
  does not mandate any one of these
- **Filtering behavior**: independent of mapping behavior, and also
  vendor-specific

**Conclusion**: sequential or otherwise predictable port allocation is a
**known possible behavior**, not a **universal rule**. Any code that assumes
"NAT usually does X" without a citation or a measured basis is writing
fiction that happens to compile.

It is also incorrect to assume the opposite — that modern routers always
randomize ports for security reasons. Some vendors do this intentionally
(aware of NAT-prediction / hole-punching research), but this is also **not
universal**. Both extremes are unverified claims until measured.

---

## 2. The layer split (F.3a / F.3b / F.3c) and why it exists

```
F.3a — Pure Math          (deterministic, 100% unit-testable, zero opinions)
   ↓
F.3b — Classification     (pattern labeling + confidence, heuristic but documented)
   ↓
F.3c — Scoring            (weapon effectiveness probabilities, requires real data)
```

This split exists specifically so that **certainty decreases visibly as you
go down the chain**, instead of being hidden inside one opaque function.
F.3a is provably correct. F.3b is a labeled hypothesis. F.3c is an
unvalidated hypothesis until measured — and the code must say so out loud.

**Status: F.3a and F.3b are implemented and fully tested (see §6 for the
decisions made during implementation that superseded this section's
original design). F.3c remains open — see §3 and §4.**

### F.3a — Pure Math (implemented)

```c
double   xury_math_mean(const uint16_t *v, size_t n);
double   xury_math_variance(const uint16_t *v, size_t n);
double   xury_math_median(const uint16_t *v, size_t n);     /* added — see §6.2 */
double   xury_math_slope(const uint16_t *v, size_t n);      /* least squares — still exists, no longer used by classify.c, see §6.2 */
bool     xury_math_is_monotonic(const uint16_t *v, size_t n);
uint16_t xury_math_predict_next(const uint16_t *v, size_t n);
```

- No NAT knowledge, no decisions, no thresholds.
- Fully testable with synthetic/fake data.
- All functions return `0.0`/`0`/`false` for `NULL`/`n==0` inputs, and
  `variance`/`median` also return `0.0` for `n==1` (no meaningful spread).

### F.3b — Classification (implemented)

```c
typedef enum {
    XURY_PATTERN_INSUFFICIENT_DATA,
    XURY_PATTERN_SEQUENTIAL_LIKE,   /* delta ≈ constant, magnitude 1 */
    XURY_PATTERN_FIXED_STEP_LIKE,   /* delta ≈ constant, magnitude > 1 */
    XURY_PATTERN_RANDOM_LIKE        /* no consistent delta */
} xury_port_pattern_t;

typedef enum {
    XURY_CONFIDENCE_LOW,
    XURY_CONFIDENCE_MEDIUM,
    XURY_CONFIDENCE_HIGH
} xury_confidence_t;

typedef struct {
    xury_port_pattern_t pattern;
    xury_confidence_t   confidence;
    uint16_t            predicted_next;   /* only meaningful if pattern != RANDOM_LIKE */
} xury_port_classification_t;

typedef struct {
    size_t min_samples;
    double variance_threshold;   /* applies to DELTA variance — see §6.1 */
    double slope_tolerance;      /* applies to median-delta near-integer check — see §6.2 */
} xury_classify_cfg_t;
```

**Current classification rule (implemented — see §6 for how this differs
from the original hypothesis below):**

1. `INSUFFICIENT_DATA` if `n < cfg->min_samples`.
2. Compute the delta array: `deltas[i] = |ports[i+1] - ports[i]|`.
3. `RANDOM_LIKE` if `variance(deltas) > cfg->variance_threshold`.
4. Otherwise compute `step = median(deltas)`. If `step` is within
   `cfg->slope_tolerance` of the nearest integer: `SEQUENTIAL_LIKE` if
   `round(step) == 1`, `FIXED_STEP_LIKE` if `round(step) > 1`.
5. `RANDOM_LIKE` otherwise.
6. Confidence scales with sample count relative to `min_samples` (simple
   buckets: `LOW` below `2×min_samples`, `MEDIUM` below `4×min_samples`,
   `HIGH` at or above).
7. `predicted_next = last_port + direction × round(step)`, where
   `direction` is the majority vote of signed
   `(ports[i+1] - ports[i])` comparisons (see §6.3), clamped to `[1, 65535]`.

**Do not write**: `if (variance < 5.0) predictable = true;` as if `5.0` is a
known constant, or as if variance applies to raw port values. See §6.1 —
this was a real bug caught during implementation.

### F.3c — Scoring (still open research — do not implement real formulas)

The 11 weapon-probability fields (`p_ipv6`, `p_upnp`, `p_hole`, ...) are
**effectiveness estimates**, not derivable from first principles. They
answer "given what we observed, how likely is weapon X to succeed?" — that
answer depends on real success/fail rates across real NAT devices, which
Xury does not yet have.

**Until real measurement data exists, F.3c functions must return an
explicit "not calibrated" error — never a guessed number:**

```c
xury_err_t xury_analysis_p_hole(const xury_scan_result_t *r, double *out);
/* Returns XURY_ERR_NOT_CALIBRATED until §4 is resolved.
 * Do NOT return a fabricated probability just to make the API "work". */
```

**Status: implemented as an honest stub.** All 11 functions in
`analysis/score.c` return `XURY_ERR_NOT_CALIBRATED` and leave the output
parameter untouched. `xury_analysis_score_calibrated()` returns `false`.
This will not change until Phase H (weapons) provides real success/fail
data — see `docs/AI_CONTEXT.md`'s note on `smart/adaptive.c`.

`XURY_ERR_NOT_CALIBRATED` is intentionally distinct from
`XURY_ERR_NOT_IMPLEMENTED`: the code path exists and is reachable, but the
constants it depends on have not been validated against reality yet. This
distinction matters for anyone auditing the codebase later — it tells them
"this is not a missing feature, this is a pending experiment."

---

## 3. Open hypotheses (starting points, not conclusions)

These are reasonable hypotheses to test, drawn from RFC 4787 categories and
general NAT literature — **not** validated claims:

| Hypothesis | Basis | Status |
|---|---|---|
| Some consumer routers use sequential/pool-based port allocation | RFC 4787 describes this as a known allocation strategy | Unverified — vendor/firmware dependent |
| Some modern routers randomize ports intentionally | Awareness of NAT-prediction attacks in security literature | Unverified — vendor/firmware dependent |
| CGNAT (carrier-grade) allocation differs from consumer router allocation | CGNAT serves many users per public IP, likely uses pooled/batch allocation | Unverified — needs ISP-level measurement |
| Symmetric NAT + sequential allocation together are exploitable (birthday-paradox style) | Documented in NAT traversal research (see `sweet/exploit/predict.c` design) | Plausible per literature, unverified for Xury's specific measurement method |

None of these should be hardcoded as fact in comments or code. Each should
be traceable to this table, and each should be marked resolved/refuted only
after real measurement.

---

## 4. What "real measurement" means for Xury

To move F.3c out of `NOT_CALIBRATED`, we need, at minimum:

1. **A measurement harness** — likely `tests/integration/test_real_network.c`
   (already scoped in the repo tree) extended to log observed port sequences
   against a labeled set of (vendor, firmware, connection type) tuples.
2. **A sample size across diverse NAT types** — home routers (multiple
   vendors), mobile carrier CGNAT, corporate NAT, cloud NAT gateways.
3. **A defined success metric** — e.g. "weapon X succeeded within N attempts
   against NAT type Y" — logged, not assumed. This is exactly what
   `smart/learning.c` Stage 1 (data collection) exists to accumulate, once
   Phase H weapons produce real attempts.
4. **A calibration process** — turning collected (features → outcome) pairs
   into the actual constants used in F.3b thresholds and F.3c probabilities.
   This is `smart/learning.c` Stage 2 / `smart/adaptive.c`'s job (Phase J),
   which can also let Xury update these constants over time instead of
   freezing them at one point-in-time guess.

Until this exists, F.3c stays `NOT_CALIBRATED` by design. This is not a
missing feature — it is the correct, honest state of the code.

---

## 5. Rule for contributors (human or AI)

- **F.3a**: implemented. Pure math — mistakes are just bugs, not research
  risk. `xury_math_slope()` still exists as a general-purpose primitive
  even though `classify.c` no longer uses it (see §6.2).
- **F.3b**: implemented with documented, labeled heuristics and multi-level
  confidence — see §6 for the exact decisions and why. Cite this file in
  the comment above any threshold.
- **F.3c**: do not implement real formulas yet. Return
  `XURY_ERR_NOT_CALIBRATED`. Add a hypothesis row to §3 if introducing a new
  weapon or probability field. Do not close this file's status as
  "resolved" without pointing to actual measurement data (§4).

If you find yourself about to write `/* NATs usually... */` as justification
for a constant — that is the signal to stop and add a row to §3 instead.

---

## 6. Decisions made during F.3b implementation (supersede §2's original hypothesis wording)

These were real bugs caught by audit-before-fix, not preferences. Anyone
touching `classify.c` should read this before changing anything.

### 6.1 Variance applies to DELTA, not to raw port values

The original hypothesis text said "variance is low" without specifying what
variance was computed over. The first implementation computed it over the
raw port values (`xury_math_variance(ports, n)`), which caused real test
failures: two equally-predictable sequences like `{5,6,7,8}` and
`{50000,50001,50002,50003}` (identical step pattern) were classified
differently, because the second sequence's raw port numbers are larger and
therefore have larger variance — even though predictability only depends on
step consistency, not on absolute port magnitude.

**Decision: variance is computed over the delta array**
(`deltas[i] = |ports[i+1]-ports[i]|`), not over `ports[]` directly. This
makes the check independent of absolute port magnitude, matching what
"predictable" actually means and matching this file's original wording
("delta ≈ constant, small variance") more literally.

This is still a hypothesis, not a validated fact — it has not been checked
against real NAT measurement (§4 still applies).

### 6.2 Step magnitude uses MEDIAN delta, not least-squares slope

The original hypothesis used least-squares slope for both the
near-integer check and `predicted_next`. This turned out to be too
sensitive to a single outlier: one repeated port value in an otherwise
perfectly sequential run (e.g. `{100,101,101,102,103}`) could drag the
slope far enough from an integer to misclassify a clearly-sequential
pattern as `RANDOM_LIKE`. This affected both `SEQUENTIAL_LIKE` and
`FIXED_STEP_LIKE` cases identically — it was not an isolated edge case.

**Decision: step magnitude is `xury_math_median(deltas, n-1)`**, not
`xury_math_slope(ports, n)`. Median is the standard robust-statistics
choice for outlier resistance and needed no threshold retuning — the
existing `variance_threshold` (2.0) and `slope_tolerance` (0.1) worked
correctly once applied to delta-variance and median-delta respectively.

`xury_math_slope()` was **not removed** — it remains a valid general-purpose
F.3a primitive. `classify.c` simply no longer calls it.

### 6.3 Direction uses majority vote of delta signs

Because deltas are stored as absolute values for the variance/median
calculations above, direction (increasing vs. decreasing sequence) is lost
unless recovered separately. Two options were rejected before landing on
the current one:

- Using the (rejected) least-squares slope's sign — reintroduces the same
  outlier fragility that median was chosen to avoid.
- Using only the first delta's sign — fragile to a single outlier at the
  start of the sequence.

**Decision: direction is the majority vote of signed
`(ports[i+1]-ports[i])` comparisons.** Ties default to `+1` (documented,
arbitrary — mainly relevant only for `RANDOM_LIKE` patterns where direction
is less meaningful anyway). Zero-deltas (repeated ports) don't count toward
either direction. `predicted_next = last_port + direction × round(median_step)`,
clamped to `[1, 65535]`.

Direction does **not** affect pattern classification
(`SEQUENTIAL_LIKE`/`FIXED_STEP_LIKE`/`RANDOM_LIKE`) — a decreasing sequence
like `{50,49,48,47}` classifies identically to its increasing counterpart,
since both are equally predictable (step magnitude 1). It only affects
which direction `predicted_next` extrapolates in.
