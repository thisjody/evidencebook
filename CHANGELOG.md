# Changelog

## Unreleased

### Added: the personal-evidence part of the third-party verifier guide

`docs/THIRD-PARTY-VERIFIER.md` §6 covers the personal-evidence disclosure
that the third-party verifier test also requires: a History at the Basic level
of the Personal-Agent History Profile v0, with the conformance vectors
published at agent-action-capsule `0b7b1825` (`vectors/personal-history-basic-v0/`,
12 cases). It says how to reproduce the vectors' responder run, the result
specified for each case, and how to report the History apart from the
service-evidence response.

- `test/interop/personal-history` is the corpus's `producer/main.go`,
  unchanged. Its test checks that it writes the corpus's `responder-run.json`
  byte for byte (`run_sha256` `f7d77d56…`), and that every value the guide
  quotes is the corpus's (`testdata/vectors.json`, pinned by digest).
- CI: a `personal-history` job reproduces the run, rebuilds the corpus from it
  with the corpus generator, and runs the corpus test, with counts per case
  class. The `interop-profile` job moves to the same agent-action-capsule
  commit, at which `vectors/interop-profile-v0/` is unchanged.
- The service-evidence part (§1 to §5) moves to the same agent-action-capsule
  commit, so the guide pins one commit. Its results follow the 53-case vectors
  that CI runs. The positive class's row `envelope-7` is `UNKNOWN`, `UNKNOWN`,
  `not_evaluable`, where the earlier vectors gave `null`. The four
  signed-absence cases are routed under missing evidence. A test pins every
  case and result the §5 table quotes against those vectors
  (`test/interop/answer/testdata/`, pinned by digest).

### Added: `BundleRequest.ProducerSignatures`

A bundle can carry each record's stored Producer Envelope inline, in the form
AAC bundle verifiers check: `signature` (the envelope, hex) and `key_id` (the
key it verifies under, hex). The envelope is the one the book stored when it
sealed the record; nothing is re-signed. A record whose stored envelope is
missing or does not verify over its record id, or whose stored capsule does not
recompute to that id, refuses the bundle with `ErrCorrupt`, before any
disclosure record is committed. Both members sit outside the capsule_id
preimage and inside the bundle digest the disclosure record commits to. Off by
default: a bundle that does not ask is unchanged.

### Added: the Rust `evidencebook` crate

The Rust implementation moved here from checkpointed-local-log with its
history (action-state-group/capsule-emit#290 stage B): `rust/evidencebook/`
in a `rust/` workspace, depending on `checkpointed-local-log` 0.3.0 from
crates.io. Rust CI (`rust.yml`: vocabulary gate, format, Clippy, tests,
rustdoc, package checks) and a crates.io publisher (`publish-rust.yml`,
`crates/evidencebook-v*` tags, separate from the Go module's `v*` tags) come
with it.

### Changed: the Evidence Request protocol comes from agent-action-capsule

The request draft's protocol logic now lives in
`github.com/action-state-group/agent-action-capsule/go/evidencerequest`
(v0.8.0), next to `draft-mih-agent-evidence-request-00` and its conformance
vectors (action-state-group/agent-action-capsule#262). evidencebook builds on
it: request parsing and validation, the JSON and CBOR encodings and digests,
resolution (`Decide` with evidencebook's share policy, derivations and refusal
policy as its `Policy`), reply parsing, refusal and envelope signing, and the
CLL proof checks and encodings. The `Book`-bound responder and requester,
storage, and the MCP and A2A carriages stay here.

- **API.** Unchanged for callers: `EvidenceRequest`, `Subject`, `Coverage`,
  `Freshness`, `Refusal`, `Anchor`, `VerificationEntry`, `Envelope`, `Reply`
  and `Message` are now aliases of the package's types (same fields), the
  reason, subject and media-type constants are the package's values, and
  `EncodeRequest` and `ParseReply` errors still match `ErrInvalid`.
  `ErrInvalid` is now `evidencerequest.ErrInvalid` itself, so errors from the
  aliased types' own methods (`Refusal.Verify`, `Envelope.Verify`) match it
  too; its message reads `evidencerequest: invalid` instead of
  `evidencebook: invalid`.
- **Behaviour.** Stricter where the package is: a JSON request or reply with
  an unpaired UTF-16 surrogate escape is malformed instead of being decoded
  with U+FFFD, and a CLL inclusion or consistency proof deeper than the MMR can
  be is refused instead of panicking.

### Changed: sealed with `github.com/action-state-group/capsule-emit/go` v0.3.0

evidencebook now imports `github.com/action-state-group/capsule-emit/go`
v0.3.0 instead of `github.com/action-state-group/capsule-emit-go` v0.1.0, which
is archived. Go treats the two paths as different modules, so a build that
uses capsule-emit with evidencebook needs the new path too.

- **Wire.** A new record's capsule carries `spec_version`
  `draft-mih-scitt-agent-action-capsule-05` instead of `-04`, so its record id
  (capsule id) differs from what the previous writer sealed for the same
  entry. The third-party verifier guide quotes the new pins and record ids of
  `test/interop/answer`.
- **Old records.** `-04` records keep verifying and keep their ids
  (`testdata/legacy-citation-purpose/` is still `-04`).

### Breaking: record capsules no longer carry the link type as `citation_purpose`

Every link on an appended record used to be sealed as a `references[]`
entry with `citation_purpose` set to the link type (`cites`, `supersedes`,
`closes`, `acknowledges`, `rebuts`, `adjudicates`). Those are Evidence
Layer link types (agent-action-capsule `spec/REGISTRY.md` §18), not
registered citation purposes (§11). The entry now carries no
`citation_purpose`, which the Capsule draft allows (`-05`, "Cross-record
references": a `references` entry MAY carry it). No link type is mapped to
a citation purpose.

- **Wire.** A new record's capsule differs from what the previous writer
  sealed for the same entry, so its record id (capsule id) differs too.
  The header, including `links[].type`, is unchanged; it stays the one
  place the link type is recorded, committed through `agent_input_digest`.
- **Old records.** Records already sealed keep verifying and keep their
  ids: nothing here reads `citation_purpose` back (link types are read from
  the header), and a verifier reports an unregistered value as
  informational, never as a rejection. A book written by the previous
  writer opens, takes new records and bundles both
  (`testdata/legacy-citation-purpose/`, `TestLegacyCitationPurposeRecordsStillVerify`).
- **Conformance.** New CI job `registry-conformance` runs the AAC
  producer-side check `agent_action_capsule.registry_conformance` (AAC
  #241, pinned to its merge commit `7fabe9a5`)
  over every capsule a book seals with each link type and a bundle
  (`test/interop/capsules`), and requires the legacy records to fail it.

### Evidence interoperability profile: A2A carriage

`Book.A2A` returns an `A2AServer` that carries the evidence request exchange
over A2A 1.0 (JSON-RPC binding) as profile `evidence-interop/0` §11.4.4
writes it (agent-action-capsule `spec/interop-profile-v0.md` at main
`1ea8f75`). It is a carriage only: `Respond` answers, and the canonical
Artifact is the one the native stream and MCP get for the same request
octets.

- **Declaration.** `AgentCard` lists one extension,
  `https://datatracker.ietf.org/doc/draft-mih-agent-evidence-request/`, with
  `required` false and `Book.Manifest` as its `params` (byte for byte the
  manifest `evidence_manifest` serves), `application/cbor` and
  `application/json` as default modes, and no skill. The card is the same
  for every caller and carries nothing about what the book holds.
- **Request and reply.** `SendMessage` with `A2A-Version` `1.0` and the
  extension in `A2A-Extensions`, whose `Message` is `ROLE_USER`, names the
  extension and holds one `raw` part of one of the two media types, is
  answered by handing the decoded octets to `Respond` unchanged. The reply,
  envelope or refusal, is a `TASK_STATE_COMPLETED` `Task` with one `Artifact`
  marked with the extension URI and one `raw` part of the request's media
  type.
- **Authorization.** `Handle(ctx, request, authenticated)` takes the
  requester the host's A2A security scheme authenticated, the same value as
  `RespondOptions.AuthenticatedRequester`. Nothing A2A carries is read as an
  identity: not an Agent Card, `metadata`, `tenant`, `contextId` or
  `messageId`.
- **Not a request, not a refusal.** A `data` or `text` part, more than one
  part, another media type, a `taskId`, another role, a missing extension or
  version, or an unwanted output mode get a JSON-RPC or A2A error, which a
  requester treats as a transport condition. No task is ever left rejected
  or failed in place of a refusal.
- **No task state, no SDK.** No task is kept: `GetTask` and `CancelTask` find
  none and `ListTasks` lists none, so no task is visible to another client.
  Identifiers are 128 random bits. Streaming, push notifications and the
  extended card are declared off and answered with A2A's errors. The JSON-RPC
  surface is implemented with the standard library and the package's strict
  JSON decoder; the host supplies the HTTP endpoint and its authentication.
- **Conformance.** The reference verifier now runs every carriage vector
  over this responder's native, A2A and MCP replies (`carriage-invariance`,
  and the A2A and MCP negative halves of §11.4.8 as mutations of its
  replies); none is skipped. CI checks the canonical Artifact is
  byte-identical across the three.

### Evidence interoperability profile: MCP carriage

`Book.MCP` returns an `MCPServer` that carries the evidence request exchange
over MCP 2026-07-28 as profile `evidence-interop/0` §11.4.5 writes it
(agent-action-capsule `spec/interop-profile-v0.md` at main `a726b9f`). It is
a carriage only: `Respond` answers, and the canonical Artifact is the one the
native stream gets for the same request octets.

- **Tools.** `tools/list` lists exactly `evidence_manifest` and
  `evidence_request`, with the profile's input and output schemas, fixed
  descriptive text and no `x-mcp-header`; the list is the same for every
  caller. `evidence_manifest` returns `Book.Manifest` as its
  `structuredContent`, byte for byte the manifest served elsewhere.
  `evidence_request` decodes the base64url `request`, hands the octets to
  `Respond` unchanged, and returns `{"reply", "media_type"}` with `isError`
  false, for an envelope and for a refusal alike.
- **Authorization.** `Handle(ctx, message, authenticated)` takes the
  requester the host's transport authenticated, the same value as
  `RespondOptions.AuthenticatedRequester`. Nothing in the MCP message is
  read as an identity: not `_meta` (`clientInfo` included), not an argument,
  not the connection.
- **Not a request, not a refusal.** Arguments outside the schema, an unknown
  tool, a missing or other protocol version, a batch or a malformed message
  get a JSON-RPC error, which a requester treats as a transport condition.
  Notifications get no response. Carriage members (`_meta`,
  `inputResponses`, `requestState`, the JSON-RPC id) never reach `Respond`.
- **No SDK.** The MCP surface the profile needs is `server/discover`,
  `tools/list` and `tools/call` over JSON-RPC 2.0, implemented here with the
  standard library and the package's strict JSON decoder. The host supplies
  the transport (stdio or Streamable HTTP) and its authentication.
- **Conformance.** The reference verifier now runs the carriage vectors over
  this responder's native and MCP replies (`carriage-invariance`, and the
  MCP negative halves of §11.4.8 as mutations of its replies); CI checks the
  canonical Artifact is byte-identical across the two. (The A2A-only
  carriage vectors were skipped until the A2A carriage, above.)

### Evidence interoperability profile (responder)

`Respond` now implements the responder side of the Minimum Evidence
Interoperability Profile `evidence-interop/0` (agent-action-capsule
`spec/interop-profile-v0.md`, read at main `6cae247` and the conformance
vectors at `5abc0da7`), over the request map of
`draft-mih-agent-evidence-request-00`. It implements only what the profile
defines.

- **Wire.** Requests are read in JSON or deterministic CBOR (`Message`: octets
  and media type) in the draft's shape: a one-member subject map,
  `expected_pin` as a digest, `min_freshness` as a size or a time. Unknown
  members are ignored; duplicate members, trailing bytes and case-variant
  names are not members. The profile's validation order decides the reason,
  so both coverage members or neither is `coverage_unsatisfiable`. The
  request digest is over the octets as received. All 33 `request.json` and
  18 of 19 `resolution.json` vectors pass (the 19th describes a log with no
  positions, which a Checkpointed Local Log cannot be).
- **Envelope.** An answer is the profile's signed envelope (`Envelope`):
  `profile`, `request_digest`, `subject`, `derivation`, `anchor` (`digest`,
  and `freshness` under `min_freshness`), `artifact_digest`, `verification`,
  `responder` and `issued_at`, signed in JCS, with the Artifact and the
  verification material beside them. The reply is in the request's encoding.
  The anchor is a checkpoint named by the SHA-256 of its signed statement.
- **Canonical Artifact.** A `record` answer is the record's own octets, proven
  with the profile's `cll-checkpoint`, `cll-inclusion-proof` and
  `cll-consistency-proof` material. Other forms use the stream binding's
  member names. No product-named member and no producer self-report.
- **Derivations.** `history_card/1` is served for `full_history` and
  `checkpoints`, to anyone. A recipient-specific projection is a derivation
  named by the digest of its definition (`RegisterDerivation`), answered only
  to its recipient, with only its declared fields.
- **Disclosure hygiene.** Every artifact is scanned against its declared field
  set and for the book's principal and counterparty references before
  release. Records of answered requests and of disclosures are never served.
- **Cost and abuse.** `Config.Responder` (`ResponderPolicy`): per-requester
  rate limits, request and answer size caps (`policy_declined`), the
  `uniform` refusal policy, `deadline_unmet`, and `retention_expired` for a
  lapsed retention commitment (`CommitRetention`). Unauthenticated and
  malformed requests never grow the log or force a checkpoint.
- **Absence.** `RecordAbsence` writes the profile's absence record
  (`AbsenceRecord`) and takes the route from the committed request.
- **Discovery.** `Manifest` returns the profile's history-free manifest.
- **SCITT stub.** Its receipts are never served as checkpoints or proofs;
  its bundle inclusion evidence is labelled `scitt-receipt-unverified`.

### Breaking

- `Respond(ctx, Message, RespondOptions)` returns `(Reply, Record, error)`.
  The old JSON request shape (`subject.kind`, `expected_pin` as
  `{root, mmr_size}`, `min_freshness` as `{size, time}`), `ArtifactResponse`,
  `Response`, `Pin` and `ParsePin` are removed. `range` positions are
  zero-based log positions.
- `RecordResponse` takes the reply `Message` as received.
  `OutcomeArtifactFailed` is now `artifact_verification_failed`;
  `refusal_nonconformant` records a signed refusal with an unregistered
  reason. `ResponseStatement.ArtifactKind` is gone; `NotChecked` lists the
  properties the profile gives no method for.
- An answer is no longer an Evidence Bundle and never carries record headers.
  Header fields are disclosed only through a registered derivation. Holder
  disclosures stay on `Bundle`, checked with `VerifyBundleAnswer`.
- An unauthenticated `min_freshness` request no longer makes the book
  checkpoint: it is answered from an existing checkpoint or refused
  `coverage_unsatisfiable`.
- `AbsenceStatement` is replaced by `AbsenceRecord`.

### Security

- `Respond` now fails closed. Protected subjects (everything except
  `checkpoints`) are answered only to a requester the transport has
  authenticated, passed in the new `RespondOptions.AuthenticatedRequester`.
  An unauthenticated caller gets only public subjects; every other request is
  answered with a signed refusal, reason `not_authorized`. This holds under
  every `history_segments` tier, including `peers`.
- A declared requester id is no longer trusted. `RespondOptions.RequesterID`
  is deprecated and ignored: it selects no relationship and grants no scope.
  Counterparty scope comes only from an authenticated identity that matches a
  `counterparty_ref`; a `counterparty_ref` value alone grants nothing.
- Requester ids are no longer stored in answerable records. The
  `evidence_request_answered` record no longer carries `requester_ref` (the
  field is removed from `AnsweredStatement`), in any form. It still records the
  request digest, subject kind, outcome, reason, relationship class and anchor.

### Breaking

- Callers that relied on `RequesterID` to unlock answers must now
  authenticate the requester at the transport and set
  `AuthenticatedRequester`. Without that change, those callers receive
  `not_authorized` for every subject except `checkpoints`.
- Records sealed before this change are immutable and still contain the
  `requester_ref` they were written with. Operators of books with such
  history should take that into account before serving `full_history` or
  `range` subjects that cover it.
