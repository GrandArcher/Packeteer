# Precedence between steering surfaces

Issue #235. Lab-proven only, not on a public edge. This page changes no behavior. It states which surface owns a prefix when several want it, what the logs say, and which test proves each pair.

## Surfaces

| Surface | What it puts on the wire | Config |
|---|---|---|
| Outbound steering | One route per improved prefix, to the chosen provider's next hop (plus its learned more-specifics with `more_specific`) | `mode: inject`, `allowlist`, `max_improvements` |
| Inbound steering | One route per `inbound.prefixes` entry while a trigger fires | `inbound` |
| Threat mitigation | One RTBH or redirect route per rule; FlowSpec rules are separate NLRI | `mitigation` |
| Leak hold | Nothing; it vetoes outbound and inbound for one prefix | `leak_watch` |
| Flap quarantine | Nothing; it vetoes outbound changes for one prefix | `flap_quarantine` |
| HA | Nothing; the standby vetoes every surface | `ha` |
| Federation | Nothing; it adds peer providers to the outbound input | `federation` |
| External policy (#232) | Not built | |

Every route that does go out is in the learned RIB, inside its allowlist, and carries `packeteer_community` and NO_EXPORT. Ownership below only decides which surface gets the prefix.

## Who owns a prefix

Ownership is per exact prefix. Highest first:

1. **Gates.** Mode other than `inject`, an HA standby, or a RIB view that is not ready: nothing is announced and everything on the wire is withdrawn.
2. **Mitigation rule** (RTBH or redirect) holding the prefix, or its route still on the wire. It takes the prefix from outbound and inbound. FlowSpec rules are not covered by the pairwise tests below.
3. **Leak hold.** Outbound and inbound leave the prefix until an operator clears it. It does not touch a mitigation rule: a rule is an operator's decision ([leak-watch.md](leak-watch.md)).
4. **Inbound.** A prefix in `inbound.prefixes` is never an outbound improvement, whether or not a steer is on the wire.
5. **Outbound.** Everything else, subject to flap quarantine and the cap.

A mitigation route, an inbound steer, and an outbound route for one prefix share one NLRI on one iBGP session, so only one of them can be on the wire. The owner above is the one that stays; the others are withdrawn, not queued, and return on their own when the owner lets go.

## Pairs

| Pair | Wins | How | Log | Test |
|---|---|---|---|---|
| Mitigation over outbound | Mitigation | Outbound withdraws its route and refuses the prefix; the rule's route stays on the wire across rounds and the outbound withdraw does not touch it | `announce` error `announce: P is reserved for inbound steering or threat mitigation` each round | `TestInteractionMitigationTakesPrefixFromOutboundSteer` |
| Mitigation over inbound | Mitigation | Inbound withdraws its steer and skips the prefix | none | `TestInteractionMitigationTakesPrefixFromInboundSteer` |
| Inbound over outbound | Inbound | The outbound announcer refuses a configured inbound prefix | same `announce` error as above | `TestInteractionInboundPrefixIsNeverAnOutboundSteer` |
| Leak hold over outbound and inbound | Hold | Outbound withdraws at once; an inbound steer is removed at its next sync | one `route seen outside the AS` warning at the sighting; a held outbound prefix is then silent | `TestHeldPrefixIsWithdrawnAndNeverAnnounced`, `TestDaemonLeakWatchWithdrawsOnlyTheLeakedRoute` |
| More-specifics | The parent improvement | A learned more-specific is announced with its parent and skipped when it is reserved, held, or outside the allowlist | none | `TestMoreSpecificReservedAndNested`, `TestHeldMoreSpecificIsNotAnnounced` |
| Quarantine over static pin | Quarantine | A parked prefix stays native whatever its cause | `flap quarantine started` / `released`, `flap.quarantined` / `flap.released` | `TestQuarantineOutranksStaticPinAndIgnoreOutranksQuarantine` |
| Ignore over quarantine | Ignore | A policy `ignore` is checked first; the quarantine keeps running | decision reason `policy ignore` | same test |
| Quarantine and HA | Standby | A leader that steps down drops its quarantine with the rest of its decision state; the next leader starts with none | `ha: standby; Packeteer routes withdrawn` | `TestInteractionQuarantineDoesNotSurviveHAHandover`, `TestDaemonHAActiveStandby` |
| HA over everything | Standby | Outbound, inbound, and mitigation check the elector under their locks before every sync | `ha standby; withdrawing ...` | `TestStandbyAnnouncesNothing`, `TestStandbyWithdrawsSteers`, `TestStandbyWithdrawsRules` |
| Federation | Local rails | Peer providers join the input only while the peer is fresh, RIB-ready, and exits that prefix through the provider; a stale peer retires the steer. Ownership above applies unchanged | `improvement retired` | `TestFederatedSteerAnnounceAndWithdraw` |

Overlapping prefixes are not conflicts. A rule for a /25 inside an improved /24 is a different NLRI; the router's longest match applies. Only a learned more-specific of an improvement is skipped when a rule or steer owns it.

## The cap

`max_improvements` counts outbound improvements and inbound steers together. It is first come, first kept: nothing on the wire is withdrawn to make room for another surface.

| Case | Result | Log | Test |
|---|---|---|---|
| Outbound holds the cap, inbound wants a steer | Steer refused | `inbound: shared max_improvements (N) reached` | `TestInteractionSharedCapOutboundFirstMitigationUncounted` |
| Inbound holds the slot, outbound wants an improvement | Improvement refused, steer kept | `announce: max_improvements (N) reached` | `TestInteractionSharedCapInboundFirstIsNotDisplaced` |
| Mitigation rules | Not counted; capped by `mitigation.max_rules` | | `TestInteractionSharedCapOutboundFirstMitigationUncounted` |
| `more_specific.max_routes` | Counts improvements, their more-specifics, and inbound steers; a new improvement is announced whole or not at all | `announce: more_specific.max_routes (N) reached` | `TestMoreSpecificRouteCapHolds` |

Known limitation: the decision engine does not know which prefixes inbound or a rule owns. It ranks them with the rest, so at the cap an owned prefix can take the decision slot, the announcer refuses it, and a lower-ranked prefix that fits on the wire stays native. Pinned by `TestInteractionOwnedPrefixStillTakesTheDecisionSlot`.

## Conflicts in the logs

There is no single conflict line today. Outbound refusals are `announce` errors, which also set `announce.failed` until a sync is clean, so an owned prefix that stays an outbound candidate keeps it set. Inbound giving way, and a held outbound prefix after the first withdraw, are silent.

## External policy (#232)

Not built. Its scope says the feed must match what inject mode would announce, so it has to publish after the ownership, cap, and quarantine rules above, not the raw decision.
