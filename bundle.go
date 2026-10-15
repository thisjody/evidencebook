// SPDX-License-Identifier: Apache-2.0

package evidencebook

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"

	aacbundle "github.com/action-state-group/agent-action-capsule/go/bundle"
	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/disclosure"
	"github.com/action-state-group/agent-action-capsule/go/envelope"
)

// PayloadsMode is the disclosure record's payloads claim.
type PayloadsMode string

const (
	PayloadsAll      PayloadsMode = "all"
	PayloadsSelected PayloadsMode = "selected"
)

// HeaderMember is the AAC disclosure member that carries a record header.
const HeaderMember = "agent_input"

// Bundle extension keys this package writes. Extensions are integrity-covered
// by the bundle digest and uninterpreted by the neutral bundle verifier.
const (
	ExtensionPayloads  = "evidencebook/payloads"
	ExtensionInclusion = "evidencebook/inclusion"
	ExtensionSubject   = "evidencebook/subject"
)

// DefaultClosureDepth is the citation depth a bundle follows from its root.
const DefaultClosureDepth = 2

// BundleRequest selects what a bundle carries and how much it discloses.
type BundleRequest struct {
	Root string
	// Include adds records to the selected set beyond the root's closure.
	Include []string
	// ClosureDepth is how many link hops to follow from Root; zero selects
	// DefaultClosureDepth.
	ClosureDepth int
	// Payloads is the disclosure claim for the selected set: all carries
	// every payload of every selected record (refused if any is unavailable),
	// selected carries those not withheld.
	Payloads PayloadsMode
	// WithholdPayloads carries headers only: every payload of the selected
	// set is withheld with its digest.
	WithholdPayloads bool
	// Suppress names disclosure members left out of the overlay; suppressing
	// HeaderMember leaves every header as withheld-with-digest.
	Suppress []string
	// Withhold names payload digests this disclosure does not carry.
	Withhold []string
	// At pins the coverage anchor; nil checkpoints the book now.
	At         *Checkpoint
	Extensions map[string]json.RawMessage
	// ProducerSignatures carries every record's stored Producer Envelope
	// inline, in the form AAC bundle verifiers check: signature, the
	// envelope as hex, and key_id, the signer's raw public key as hex
	// (KeyID's convention), read from the envelope once it verifies over the
	// record id. Both sit outside the capsule_id preimage and inside the
	// bundle digest the disclosure record commits to. Nothing is re-signed:
	// a record without a stored envelope, whose envelope does not verify, or
	// whose stored capsule does not recompute to its id refuses the bundle
	// with ErrCorrupt.
	ProducerSignatures bool
}

// Bundle is a portable, self-verifying Evidence Bundle v2 plus the disclosure
// record the book committed about it.
type Bundle struct {
	JSON       []byte
	Digest     string
	Anchor     Checkpoint
	Disclosure Record
}

// WithheldItem names material committed but not carried, always with its digest.
type WithheldItem struct {
	RecordID          string         `json:"record_id"`
	Member            string         `json:"member,omitempty"`
	PayloadCommitment string         `json:"payload_commitment,omitempty"`
	Digest            string         `json:"digest"`
	RetentionState    RetentionState `json:"retention_state,omitempty"`
}

// DisclosureStatement is the body of a disclosure record (Evidence Layer §6.2).
type DisclosureStatement struct {
	BundleDigest     string         `json:"bundle_digest"`
	Anchor           string         `json:"anchor"`
	Payloads         PayloadsMode   `json:"payloads"`
	SuppressedFields []string       `json:"suppressed_fields"`
	Withheld         []WithheldItem `json:"withheld"`
}

type completenessClaim struct {
	ClosureDepth     int          `json:"closure_depth"`
	RecordsMode      string       `json:"records_mode"`
	PayloadsMode     PayloadsMode `json:"payloads_mode"`
	SuppressedFields []string     `json:"suppressed_fields"`
	Missing          []string     `json:"missing"`
}

type producerReport struct {
	Producer string   `json:"producer"`
	Checks   []string `json:"checks"`
}

type bundleWire struct {
	BundleVersion string                                `json:"bundle_version"`
	BundleKind    string                                `json:"bundle_kind"`
	Root          string                                `json:"root"`
	Records       []json.RawMessage                     `json:"records"`
	Completeness  completenessClaim                     `json:"completeness"`
	Certificate   *CompletenessCertificate              `json:"completeness_certificate,omitempty"`
	Checkpoint    *BundleCheckpoint                     `json:"checkpoint,omitempty"`
	Disclosures   map[string]map[string]json.RawMessage `json:"disclosures"`
	Extensions    map[string]json.RawMessage            `json:"extensions,omitempty"`
	Verification  producerReport                        `json:"verification"`
}

// Bundle resolves the root's citation closure, constructs the disclosure,
// asks the substrate for interval and membership evidence under one anchor,
// and returns a portable bundle. It then commits a disclosure record citing
// every record whose header or payload the bundle disclosed.
func (b *Book) Bundle(ctx context.Context, req BundleRequest) (Bundle, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.bundleLocked(ctx, req)
}

func (b *Book) bundleLocked(ctx context.Context, req BundleRequest) (Bundle, error) {
	if req.Payloads == "" {
		req.Payloads = PayloadsSelected
	}
	if req.Payloads != PayloadsAll && req.Payloads != PayloadsSelected {
		return Bundle{}, fmt.Errorf("%w: payloads must be all or selected", ErrInvalid)
	}
	if req.ClosureDepth == 0 {
		req.ClosureDepth = DefaultClosureDepth
	}
	if req.Payloads == PayloadsAll && len(req.Withhold) > 0 {
		return Bundle{}, fmt.Errorf("%w: payloads=all cannot withhold payloads", ErrInvalid)
	}
	selected, missing, err := b.closureLocked(req.Root, req.ClosureDepth)
	if err != nil {
		return Bundle{}, err
	}
	for _, id := range req.Include {
		if _, ok := b.records[id]; !ok {
			return Bundle{}, fmt.Errorf("%w: included record %s", ErrNotFound, id)
		}
		selected[id] = struct{}{}
	}
	anchor, err := b.anchorLocked(ctx, req.At)
	if err != nil {
		return Bundle{}, err
	}
	first := anchor.Entries
	for id := range selected {
		seq := b.records[id].Seq
		if !anchor.Covers(seq) {
			return Bundle{}, fmt.Errorf("%w: record %s (seq %d) under %s", ErrNotCovered, id, seq, anchor.ID)
		}
		first = min(first, seq)
	}

	wire := bundleWire{
		BundleVersion: "2", BundleKind: "evidence-bundle/v2", Root: req.Root,
		Disclosures:  make(map[string]map[string]json.RawMessage),
		Extensions:   make(map[string]json.RawMessage),
		Verification: producerReport{Producer: DefaultDeveloper, Checks: []string{"graph_closure", "interval_coverage", "per_record_membership"}},
	}
	var carried []string
	interval, err := b.commitments.ProveInterval(ctx, first, anchor)
	switch {
	case err == nil:
		wire.Certificate, wire.Checkpoint = &interval.Certificate, &interval.Checkpoint
		for seq := first; seq <= anchor.Entries; seq++ {
			carried = append(carried, b.order[seq-1])
		}
	case errors.Is(err, ErrUnsupported):
		inclusion := make(map[string]InclusionEvidence)
		for id := range selected {
			if inclusion[id], err = b.commitments.ProveInclusion(ctx, b.records[id].Seq, anchor); err != nil {
				return Bundle{}, err
			}
			carried = append(carried, id)
		}
		sort.Slice(carried, func(i, j int) bool { return b.records[carried[i]].Seq < b.records[carried[j]].Seq })
		if wire.Extensions[ExtensionInclusion], err = json.Marshal(inclusion); err != nil {
			return Bundle{}, err
		}
	default:
		return Bundle{}, err
	}

	// Only the selected set is ever disclosed. Other records in the interval
	// ride along as digest-only capsules so membership can be proved.
	disclosed := slices.DeleteFunc(slices.Clone(carried), func(id string) bool { _, ok := selected[id]; return !ok })
	statement := DisclosureStatement{Anchor: anchor.ID, Payloads: req.Payloads, SuppressedFields: append([]string{}, req.Suppress...), Withheld: []WithheldItem{}}
	payloads := make(map[string]string)
	for _, id := range carried {
		stored, err := b.storedLocked(ctx, id)
		if err != nil {
			return Bundle{}, err
		}
		capsule := stored.Capsule
		if req.ProducerSignatures {
			if capsule, err = signedCapsule(id, stored); err != nil {
				return Bundle{}, err
			}
		}
		wire.Records = append(wire.Records, capsule)
		if !slices.Contains(disclosed, id) {
			statement.Withheld = append(statement.Withheld, WithheldItem{RecordID: id, Member: HeaderMember, Digest: digestBytes(stored.Header)})
		}
	}
	for _, id := range disclosed {
		stored, err := b.storedLocked(ctx, id)
		if err != nil {
			return Bundle{}, err
		}
		if slices.Contains(req.Suppress, HeaderMember) {
			statement.Withheld = append(statement.Withheld, WithheldItem{RecordID: id, Member: HeaderMember, Digest: digestBytes(stored.Header)})
		} else {
			wire.Disclosures[id] = map[string]json.RawMessage{HeaderMember: stored.Header}
		}
		for _, digest := range b.records[id].Header.PayloadCommitments {
			if req.WithholdPayloads || slices.Contains(req.Withhold, digest) {
				if req.Payloads == PayloadsAll {
					return Bundle{}, fmt.Errorf("%w: payloads=all cannot withhold payloads", ErrInvalid)
				}
				statement.Withheld = append(statement.Withheld, WithheldItem{RecordID: id, PayloadCommitment: digest, Digest: digest})
				continue
			}
			data, err := b.resolveLocked(ctx, id, digest)
			var unavailable *UnavailableError
			if errors.As(err, &unavailable) {
				if req.Payloads == PayloadsAll {
					return Bundle{}, fmt.Errorf("%w: payloads=all but %s is %s", ErrInvalid, digest, unavailable.State)
				}
				statement.Withheld = append(statement.Withheld, WithheldItem{RecordID: id, PayloadCommitment: digest, Digest: digest, RetentionState: unavailable.State})
				continue
			}
			if err != nil {
				return Bundle{}, err
			}
			payloads[digest] = base64.RawURLEncoding.EncodeToString(data)
		}
	}
	if len(payloads) > 0 {
		if wire.Extensions[ExtensionPayloads], err = json.Marshal(payloads); err != nil {
			return Bundle{}, err
		}
	}
	for key, value := range req.Extensions {
		wire.Extensions[key] = value
	}
	if len(wire.Extensions) == 0 {
		wire.Extensions = nil
	}
	wire.Completeness = completenessClaim{ClosureDepth: req.ClosureDepth, RecordsMode: "complete", PayloadsMode: req.Payloads, SuppressedFields: statement.SuppressedFields, Missing: missing}
	if len(missing) > 0 {
		wire.Completeness.RecordsMode = "declared_incomplete"
	}
	data, err := canonicalJSON(wire)
	if err != nil {
		return Bundle{}, err
	}
	statement.BundleDigest = digestBytes(data)
	body, err := json.Marshal(statement)
	if err != nil {
		return Bundle{}, err
	}
	links := make([]Link, 0, len(disclosed))
	for _, id := range disclosed {
		links = append(links, Link{Type: Cites, Target: id})
	}
	record, err := b.appendLocked(ctx, Entry{RecordType: RecordTypeDisclosure, EpistemicType: ProducerClaim, Links: links, Statement: body})
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{JSON: data, Digest: statement.BundleDigest, Anchor: anchor, Disclosure: record}, nil
}

// signedCapsule is a stored record's capsule with its Producer Envelope
// inline (see BundleRequest.ProducerSignatures). The envelope is the one the
// book stored when it sealed the record; it must verify over the record id,
// and key_id is the key it verifies under.
func signedCapsule(id string, stored StoredRecord) (json.RawMessage, error) {
	if stored.RecordID != id {
		return nil, fmt.Errorf("%w: record %s: store returned record %s", ErrCorrupt, id, stored.RecordID)
	}
	if len(stored.Envelope) == 0 {
		return nil, fmt.Errorf("%w: record %s has no stored Producer Envelope", ErrCorrupt, id)
	}
	verified := envelope.Verify(id, stored.Envelope)
	if !verified.OK || len(verified.PublicKey) == 0 {
		return nil, fmt.Errorf("%w: record %s: stored Producer Envelope does not verify over its record id", ErrCorrupt, id)
	}
	decoded, err := decodeJSON(stored.Capsule)
	if err != nil {
		return nil, fmt.Errorf("%w: record %s: stored capsule: %v", ErrCorrupt, id, err)
	}
	capsule, ok := decoded.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: record %s: stored capsule is not a JSON object", ErrCorrupt, id)
	}
	for _, member := range []string{"signature", "key_id"} {
		if _, present := capsule[member]; present {
			return nil, fmt.Errorf("%w: record %s: stored capsule already carries %s", ErrCorrupt, id, member)
		}
	}
	if recomputed, err := canonical.ComputeCapsuleID(capsule); err != nil || recomputed != id {
		return nil, fmt.Errorf("%w: record %s: stored capsule does not recompute to its record id", ErrCorrupt, id)
	}
	capsule["signature"] = hex.EncodeToString(stored.Envelope)
	capsule["key_id"] = hex.EncodeToString(verified.PublicKey)
	return json.Marshal(capsule)
}

// closureLocked walks links from root up to depth hops. Targets the book does
// not hold are returned as missing, never silently dropped.
func (b *Book) closureLocked(root string, depth int) (map[string]struct{}, []string, error) {
	if _, ok := b.records[root]; !ok {
		return nil, nil, fmt.Errorf("%w: bundle root %s", ErrNotFound, root)
	}
	selected := map[string]struct{}{root: {}}
	missing := map[string]struct{}{}
	frontier := []string{root}
	for range depth {
		var next []string
		for _, id := range frontier {
			for _, link := range b.records[id].Header.Links {
				if _, held := b.records[link.Target]; !held {
					missing[link.Target] = struct{}{}
					continue
				}
				if _, seen := selected[link.Target]; !seen {
					selected[link.Target] = struct{}{}
					next = append(next, link.Target)
				}
			}
		}
		frontier = next
	}
	out := make([]string, 0, len(missing))
	for id := range missing {
		out = append(out, id)
	}
	sort.Strings(out)
	return selected, out, nil
}

func (b *Book) anchorLocked(ctx context.Context, at *Checkpoint) (Checkpoint, error) {
	if at == nil {
		return b.checkpointLocked(ctx)
	}
	history, err := b.store.Checkpoints(ctx)
	if err != nil {
		return Checkpoint{}, err
	}
	for _, cp := range history {
		if cp.ID == at.ID && cp.LogID == at.LogID {
			return cp, nil
		}
	}
	return Checkpoint{}, fmt.Errorf("%w: checkpoint %s was not issued by this book", ErrNotFound, at.ID)
}

// strictDecode decodes raw into T only if re-encoding the result reproduces
// raw's canonical form exactly. Any key the struct would ignore, merge, or
// match case-insensitively (an unknown field, a duplicate "seq"/"SEQ") makes
// the two differ, so the value is refused rather than read differently from
// other implementations.
func strictDecode[T any](raw json.RawMessage) (T, error) {
	var zero, out T
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		return zero, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	disclosed, err := decodeJSON(raw)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	want, err := canonical.JCS(disclosed)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	got, err := canonicalJSON(out)
	if err != nil || !bytes.Equal(got, want) {
		return zero, fmt.Errorf("%w: value does not re-encode to what was disclosed", ErrInvalid)
	}
	return out, nil
}

// strictHeader decodes a disclosed header strictly and validates it.
func strictHeader(raw json.RawMessage) (Header, error) {
	header, err := strictDecode[Header](raw)
	if err != nil {
		return Header{}, err
	}
	return header, validateHeader(header)
}

// PeerRecord is one record read from a verified bundle. Header is nil when
// the bundle withheld it; HeaderVerified is true only when the disclosed
// header hashes to the digest the record's capsule commits.
type PeerRecord struct {
	RecordID       string
	Seq            uint64
	Header         *Header
	HeaderVerified bool
	CapsuleOK      bool
}

// VerifiedBundle is what a relying party learns from a bundle after the
// neutral Evidence Bundle verifier has checked it. AnchorAuthenticated means
// the checkpoint statement verifies under the key it names (AnchorKeyID);
// whether that key and log belong to the party the relying party expects is
// the relying party's check, against a key it obtained independently.
type VerifiedBundle struct {
	Digest              string
	LogID               string
	Anchor              BundleCheckpoint
	AnchorAuthenticated bool
	AnchorKeyID         string
	// AnchorStatement is the anchor's signed checkpoint statement, when
	// AnchorAuthenticated.
	AnchorStatement []byte
	// Witnesses are the witness receipts the bundle carries
	// (checkpoint.witnesses), as given. Nothing here verifies them: a
	// requester checks them against the anchor under its own witness
	// directory (RecordResponse does, through ResponderKeys.Witnesses).
	Witnesses     []json.RawMessage
	IntervalFirst uint64
	IntervalLast  uint64
	Records       []PeerRecord
	Payloads      map[string][]byte
	// Extensions are integrity-covered by the bundle digest but are the
	// producer's statements; nothing in them is independently verified.
	Extensions map[string]json.RawMessage
	Findings   []string
	// Claims is each of the three verifier claims' status ("pass",
	// "withheld", "unverified", ...). VerifyBundle refuses only "fail";
	// FullyVerified reports whether everything passed.
	Claims BundleClaims
}

// BundleClaims is the status of each Evidence Bundle verifier claim.
type BundleClaims struct {
	GraphClosure        string
	IntervalCoverage    string
	PerRecordMembership string
}

// FullyVerified returns nil only when all three claims passed and every
// record's capsule verified. VerifyBundle accepts a bundle whose claims are
// "withheld" or "unverified" (nothing in it is false); a caller that treats
// the bundle as proof of what it answers must also require this.
func (v VerifiedBundle) FullyVerified() error {
	for name, status := range map[string]string{
		"graph closure":         v.Claims.GraphClosure,
		"interval coverage":     v.Claims.IntervalCoverage,
		"per-record membership": v.Claims.PerRecordMembership,
	} {
		if status != "pass" {
			return fmt.Errorf("%w: bundle %s is %q, not pass", ErrInvalid, name, status)
		}
	}
	for _, record := range v.Records {
		if !record.CapsuleOK {
			return fmt.Errorf("%w: bundle record %s does not verify as a capsule", ErrInvalid, record.RecordID)
		}
	}
	return nil
}

// Covers reports whether the bundle proves seq is inside its authenticated interval.
func (v VerifiedBundle) Covers(seq uint64) bool {
	return v.AnchorAuthenticated && seq >= v.IntervalFirst && seq <= v.IntervalLast
}

// VerifyBundleAnswer checks an Evidence Bundle a holder disclosed to this
// requester (Book.Bundle) under the holder's pinned keys: the neutral bundle
// verifier must pass every claim, the anchor must be a checkpoint signed by
// keys.Checkpoint, and every witness receipt carried on it must verify
// against that checkpoint under the requester's own witness directory. A
// bundle is never the canonical Artifact of an evidence request; this is the
// separate disclosure path (profile §6.6).
func VerifyBundleAnswer(data []byte, keys ResponderKeys) (VerifiedBundle, error) {
	if keys.Checkpoint == "" {
		return VerifiedBundle{}, fmt.Errorf("%w: a pinned checkpoint key is required", ErrInvalid)
	}
	verified, err := VerifyBundle(data)
	if err != nil {
		return verified, err
	}
	if err := verified.FullyVerified(); err != nil {
		return verified, err
	}
	if !verified.AnchorAuthenticated || verified.AnchorKeyID != keys.Checkpoint {
		return verified, fmt.Errorf("%w: bundle is not anchored to a checkpoint signed by the pinned key", ErrInvalid)
	}
	if err := verifyCarriedReceipts(verified.AnchorStatement, verified.Witnesses, keys.Witnesses); err != nil {
		return verified, err
	}
	return verified, nil
}

// VerifyBundle checks a bundle with the neutral AAC Evidence Bundle verifier
// and then reads the evidence-layer content out of what verified. It never
// trusts the producer's own verification member.
//
// Everything is read from the one decoded tree the verifier checked, by
// exact key, so the verifier and this reader can never see different
// members: a second copy of a member under a case-variant key ("Disclosures",
// "CHECKPOINT") is refused outright, and a member present only under a
// case-variant key is simply absent, exactly as the verifier sees it.
func VerifyBundle(data []byte) (VerifiedBundle, error) {
	decoded, err := decodeJSON(data)
	if err != nil {
		return VerifiedBundle{}, fmt.Errorf("%w: bundle JSON: %v", ErrInvalid, err)
	}
	tree := jsonNode{value: decoded}
	if !tree.isObject() {
		return VerifiedBundle{}, fmt.Errorf("%w: bundle is not a JSON object", ErrInvalid)
	}
	if err := rejectFoldedKeys(tree, "$"); err != nil {
		return VerifiedBundle{}, err
	}
	result := aacbundle.VerifyBundle(decoded)
	out := VerifiedBundle{
		Payloads:   make(map[string][]byte),
		Extensions: make(map[string]json.RawMessage),
		Claims: BundleClaims{
			GraphClosure:        result.GraphClosure.Status,
			IntervalCoverage:    result.IntervalCoverage.Status,
			PerRecordMembership: result.PerRecordMembership.Status,
		},
	}
	if result.BundleDigest != nil {
		out.Digest = *result.BundleDigest
	}
	for _, claim := range []aacbundle.ClaimResult{result.GraphClosure, result.IntervalCoverage, result.PerRecordMembership} {
		if claim.Status == "fail" {
			return out, fmt.Errorf("%w: bundle verification failed: %v", ErrInvalid, claim.Findings)
		}
		out.Findings = append(out.Findings, claim.Findings...)
	}
	certificate, checkpointMember := tree.get("completeness_certificate"), tree.get("checkpoint")
	if certificate.isObject() && checkpointMember.isObject() {
		out.LogID, _ = certificate.get("log_id").str()
		out.IntervalFirst, _ = certificate.get("first_seq").uint()
		out.IntervalLast, _ = certificate.get("last_seq").uint()
		// A checkpoint that states a log id states it as a non-empty
		// string; anything else there (a number, null, "") is refused rather
		// than read as stating none.
		logIDStated := checkpointMember.has("log_id")
		if logIDStated {
			var ok bool
			if out.Anchor.LogID, ok = checkpointMember.get("log_id").str(); !ok || out.Anchor.LogID == "" {
				return out, fmt.Errorf("%w: checkpoint log_id is not a non-empty string", ErrInvalid)
			}
		}
		out.Anchor.Root, _ = checkpointMember.get("root").str()
		out.Anchor.MMRSize, _ = checkpointMember.get("mmr_size").uint()
		out.Anchor.COSE, _ = checkpointMember.get("cose").str()
		out.AnchorAuthenticated = result.IntervalCoverage.Status == "pass" && !slices.Contains(result.IntervalCoverage.Findings, "checkpoint_unverified")
		if out.AnchorAuthenticated {
			statement, err := base64.RawURLEncoding.DecodeString(out.Anchor.COSE)
			if err != nil {
				return out, fmt.Errorf("%w: checkpoint statement: %v", ErrInvalid, err)
			}
			cp, err := checkpointFromStatement(statement)
			if err != nil {
				return out, err
			}
			if cp.Root != out.Anchor.Root || cp.TreeSize != out.Anchor.MMRSize || cp.LogID != out.LogID || logIDStated && out.Anchor.LogID != cp.LogID {
				return out, fmt.Errorf("%w: checkpoint statement does not name the verified interval", ErrInvalid)
			}
			out.AnchorKeyID = cp.KeyID
			out.AnchorStatement = statement
		}
		// A witnesses member, when present, is an array of receipts. Any other
		// value (a lone receipt object, a string, null) is malformed: read as
		// absent, it would let an answer's receipts go unchecked.
		if stated, present := checkpointMember.value.(map[string]any)["witnesses"]; present {
			if _, isArray := stated.([]any); !isArray {
				return out, fmt.Errorf("%w: checkpoint.witnesses is not an array", ErrInvalid)
			}
		}
		for _, entry := range checkpointMember.get("witnesses").items() {
			raw, err := entry.canonical()
			if err != nil {
				return out, fmt.Errorf("%w: witness receipt: %v", ErrInvalid, err)
			}
			out.Witnesses = append(out.Witnesses, raw)
		}
	}
	extensions := tree.get("extensions")
	for _, key := range extensions.keys() {
		if out.Extensions[key], err = extensions.get(key).canonical(); err != nil {
			return out, fmt.Errorf("%w: extension %s: %v", ErrInvalid, key, err)
		}
	}
	matched := make(map[string]bool)
	for _, d := range result.Disclosures {
		if d.Member == HeaderMember && d.Status == disclosure.Match {
			matched[d.CapsuleID] = true
		}
	}
	for _, record := range tree.get("records").items() {
		id, ok := record.get("capsule_id").str()
		if !ok {
			return out, fmt.Errorf("%w: bundle record has no capsule_id", ErrInvalid)
		}
		peer := PeerRecord{RecordID: id, CapsuleOK: result.CapsuleResults[id].OK}
		peer.Seq, _ = certificate.get("memberships").get(id).get("log_coordinates").get("seq").uint()
		if header := tree.get("disclosures").get(id).get(HeaderMember); header.present() && matched[id] {
			raw, err := header.canonical()
			if err != nil {
				return out, fmt.Errorf("%w: disclosed header: %v", ErrInvalid, err)
			}
			if parsed, err := strictHeader(raw); err == nil {
				peer.Header, peer.HeaderVerified = &parsed, true
			}
		}
		out.Records = append(out.Records, peer)
	}
	payloads := extensions.get(ExtensionPayloads)
	for _, digest := range payloads.keys() {
		value, ok := payloads.get(digest).str()
		if !ok {
			return out, fmt.Errorf("%w: disclosed payload %s is not a string", ErrInvalid, digest)
		}
		data, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || digestBytes(data) != digest {
			return out, fmt.Errorf("%w: disclosed payload does not hash to %s", ErrInvalid, digest)
		}
		out.Payloads[digest] = data
	}
	return out, nil
}
