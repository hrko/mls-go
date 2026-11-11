# AsterinMusic maintenance fork

Base: upstream `20ed0bb2b7a3219118cf79f9f6f534488d756b76` (unreleased after
v1.6.0, including PRs #122, #126, #132 and #135). The original module path is
preserved. Consumers must pin this fork with a main-module replace directive;
dependency-module replacements are not inherited by Go.

## Proposal stream boundary

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
