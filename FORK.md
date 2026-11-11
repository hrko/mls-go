# AsterinMusic maintenance fork

Base: upstream `20ed0bb2b7a3219118cf79f9f6f534488d756b76` (unreleased after
v1.6.0, including PRs #122, #126, #132 and #135). The original module path is
preserved. Consumers must pin this fork with a main-module replace directive;
dependency-module replacements are not inherited by Go.

## Proposal stream boundary

Tracking ID: MLS-PREFIX-01. Status: fork-only. Remove this delta when upstream
provides deterministic public-Proposal prefix parsing with the same exact-length
and failure contract, and the prefix regression tests pass against that API.

DAVE opcode 27 contains a TLS vector of concatenated MLSMessages. Calling the
complete-message parser with that entire vector fails when the first proposal's
authentication tail is followed by another message. This is reproduced on both
v1.6.0 and the upstream base above; upstream's linear-body-boundary fix does not
provide prefix parsing.

`framing.UnmarshalMLSProposalPrefix` returns one public Proposal message and the
exact consumed wire length. It uses the registered deterministic proposal decoder
and TLS lengths, never scans for a plausible authentication tail. It requires the
group package's decoder registration, rejects other content/wire formats, and
returns nil/zero on failure. Existing unmarshalling APIs retain their behavior.
This API does not authenticate messages: callers still verify signatures, tags,
group/epoch and proposal policy through normal MLS processing.

The API is intentionally limited to public Proposals. It does not claim to parse
arbitrary concatenated Commit, Welcome, GroupInfo, or KeyPackage messages.

## Validation

- External/member/new-member proposal prefixes, exact lengths, every truncated
  prefix, invalid version/sender/content/body, and missing/invalid decoder.
- Existing MLS interop proposal vectors with a second message appended.
- A 15-second fuzz run passed with 5,031,672 inputs; repeat for future changes.
- dave-go integration covers a two-Add batch, both joiners in the pending epoch,
  revoke/recommit from that batch, unchanged state on malformed framing, and bad
  signature rejection. Official libdave and the fork accept the same signed batch.
- Windows full-suite failure: file-store directory Sync returns Access denied,
  also reproduced on unmodified upstream. AsterinMusic uses the memory store.
  This is not fixed or hidden by this patch, and the full Windows suite must not
  be reported as passing. No claim of a complete MLS security audit is made.

Keep this patch separate from broader MLS changes and propose it upstream after
review. Do not infer that it fixes the observed live DAVE readiness timeout.

## MLS-CANDIDATE-01: independent Commit candidates (in development)

Base: `634fb81d9a189dcbf4eed3b8148e816b5a9767f0`. Reference behavior:
libdave `b5463c443df74db75a713c775b09a847621e6d62`, MLS Session
ProcessProposals/ProcessCommit. DAVE sends Commit and Welcome together before
the gateway selects a candidate; multiple candidates can belong to one epoch.
The existing staged API pins a pending group and delays Welcome until confirm,
so it cannot directly serve that delivery model.

`PrepareCommitCandidate` mutates a deserialized group copy using the owning
client's signing identity. It returns Commit and Welcome without changing the
live state, emitting events or exposing a signature private key. Candidates own
private serialized group snapshots and must be closed after use. They do not
pin the client or delay Client.Close. `AdoptCommitCandidate` checks ownership
and exact current-state equality before persisting the selected next state.
It does not switch DAVE media keys. Caller-level DAVE validation is still required.

The initial API deliberately emits no GroupEvents. Its adoption currently uses
the existing multi-write persistGroup contract; durable-store partial failures
are not made transactional by this change. AsterinMusic uses memory storage.
These limitations must be resolved or explicitly retained before publishing the
API as general-purpose. Temporary group objects are GC-managed; Close clears
the candidate's serialized private-state buffers, not all heap copies made by MLS.

Validation: `go test . -run TestCommitCandidate -count=1` covers independent
generation, selecting a candidate, stale/foreign/discarded candidates, changed
proposals, closed clients, cancelled contexts and matching Welcome exporter keys.
Full integration and persistence-failure/concurrency validation remain pending.

Status: fork-only, not yet deployed. No upstream PR exists. Remove or replace
this delta when upstream supports isolated, selectable Commit/Welcome candidates
without advancing the live group, and these tests plus DAVE event-sequence tests
pass. Preserve the difference from generic RFC staged-commit APIs in that review.
