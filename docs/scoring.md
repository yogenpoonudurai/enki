# Posture scoring

The posture score is deterministic and intentionally soft at the bottom end.

## Penalties

| Severity | Weight |
|---|---|
| CRITICAL | 20 |
| HIGH | 10 |
| MEDIUM | 4 |
| LOW | 1 |
| INFO | 0 |

Penalties are summed **per module** and capped at 40 per module, so a noisy
dependency scan cannot erase the signal from agent or endpoint checks.

## Compression

```
score = round( 10000 / (100 + totalPenalty) )
```

Examples:

| Total penalty | Score |
|---|---|
| 0 | 100 |
| 15 | 87 |
| 40 | 71 |
| 100 | 50 |
| 200 | 33 |
| 500 | 17 |

The earlier linear formula (`100 - penalty`) hit zero on ordinary developer
machines with a busy dependency graph. Compression keeps the score useful as a
trend indicator while the verdict and severity counts carry the urgency.

## Verdict

| Condition | Verdict |
|---|---|
| any CRITICAL | AT RISK |
| any HIGH | ATTENTION |
| any MEDIUM | REVIEW |
| otherwise | GOOD |

Coverage gaps (for example "osv.dev unreachable") never improve the score;
they are reported separately so that "unknown" is never presented as "clean".
A gap carries a kind — `network`, `permission`, `unsupported`, `truncated`,
`error`, or `not-applicable` — and, where relevant, the scope it belongs to.

When there are no findings but a real gap exists, the verdict is
`GOOD (partial)`. `not-applicable` gaps come from scope selection (`--scope
project` skips host checks and vice versa) and do not downgrade the verdict.
Each module also reports whether it was skipped, how many gaps it produced,
and its runtime.
