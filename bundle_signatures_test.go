// SPDX-License-Identifier: Apache-2.0

package evidencebook

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/envelope"
)

// TestBundleCarriesStoredProducerSignatures: with ProducerSignatures, every
// carried record holds its stored Producer Envelope inline (signature) and
// the key it verifies under (key_id). The envelope is the stored one, byte
// for byte, the capsule ids do not move, the neutral verifier still passes,
// and the disclosure record commits to the bundle as emitted.
func TestBundleCarriesStoredProducerSignatures(t *testing.T) {
	ctx := context.Background()
	book, records := linkedBook(t)
	bundle, err := book.Bundle(ctx, BundleRequest{Root: records[2].RecordID, ProducerSignatures: true})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeJSON(bundle.JSON)
	if err != nil {
		t.Fatal(err)
	}
	carried := decoded.(map[string]any)["records"].([]any)
	if len(carried) == 0 {
		t.Fatal("bundle carries no records")
	}
	for _, raw := range carried {
		capsule := raw.(map[string]any)
		id := capsule["capsule_id"].(string)
		stored, err := book.store.GetRecord(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		signature, _ := capsule["signature"].(string)
		if signature != hex.EncodeToString(stored.Envelope) {
			t.Fatalf("record %s: signature is not its stored envelope", id)
		}
		if capsule["key_id"] != KeyID(book.signer) {
			t.Fatalf("record %s: key_id %v, want the book's signer %s", id, capsule["key_id"], KeyID(book.signer))
		}
		envelopeBytes, _ := hex.DecodeString(signature)
		if verified := envelope.Verify(id, envelopeBytes); !verified.OK {
			t.Fatalf("record %s: inline envelope does not verify: %+v", id, verified.Findings)
		}
		recomputed, err := canonical.ComputeCapsuleID(capsule)
		if err != nil || recomputed != id {
			t.Fatalf("record %s: capsule id moved to %s (%v)", id, recomputed, err)
		}
	}
	result := aacVerify(t, bundle.JSON)
	if result.GraphClosure.Status != "pass" || result.IntervalCoverage.Status != "pass" || result.PerRecordMembership.Status != "pass" {
		t.Fatalf("neutral verifier: %+v %+v %+v", result.GraphClosure, result.IntervalCoverage, result.PerRecordMembership)
	}
	if result.BundleDigest == nil || *result.BundleDigest != bundle.Digest {
		t.Fatal("bundle digest differs from the verifier's")
	}
	if !strings.Contains(string(bundle.Disclosure.Header.Statement), bundle.Digest) {
		t.Fatal("disclosure record does not commit to the bundle as emitted")
	}
	if _, err := VerifyBundle(bundle.JSON); err != nil {
		t.Fatal(err)
	}

	// Without the option a bundle is unchanged: no record carries either member.
	plain, err := book.Bundle(ctx, BundleRequest{Root: records[2].RecordID})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain.JSON, []byte(`"signature"`)) || bytes.Contains(plain.JSON, []byte(`"key_id":"`+KeyID(book.signer))) {
		t.Fatal("a bundle that did not ask for producer signatures carries them")
	}
}

// envelopeTamperStore returns one record with its stored envelope replaced.
type envelopeTamperStore struct {
	Store
	target   string
	envelope []byte
}

func (s envelopeTamperStore) GetRecord(ctx context.Context, id string) (StoredRecord, error) {
	record, err := s.Store.GetRecord(ctx, id)
	if err == nil && id == s.target {
		record.Envelope = s.envelope
	}
	return record, err
}

// TestBundleRefusesAnUnverifiableStoredEnvelope: a stored envelope that is
// missing, or does not verify over its record id (here, another record's
// valid envelope), refuses the bundle. Nothing is re-signed, and no
// disclosure record is committed.
func TestBundleRefusesAnUnverifiableStoredEnvelope(t *testing.T) {
	ctx := context.Background()
	fixture := newFixture(t, "book-a", 1)
	book := fixture.open(t)
	observed := mustAppend(t, book, observation("order-17", `{"status":"approved"}`))
	claim := mustAppend(t, book, Entry{RecordType: "claim", EpistemicType: ProducerClaim, SubjectRef: "order-17", Links: []Link{{Type: Cites, Target: observed.RecordID}}})
	other, err := book.store.GetRecord(ctx, observed.RecordID)
	if err != nil {
		t.Fatal(err)
	}
	for name, replacement := range map[string][]byte{"missing": nil, "another record's": other.Envelope} {
		before, err := book.Query(ctx, Filter{RecordType: RecordTypeDisclosure})
		if err != nil {
			t.Fatal(err)
		}
		real := book.store
		book.store = envelopeTamperStore{Store: real, target: claim.RecordID, envelope: replacement}
		_, err = book.Bundle(ctx, BundleRequest{Root: claim.RecordID, ProducerSignatures: true})
		book.store = real
		if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), claim.RecordID) {
			t.Fatalf("%s envelope: bundle built (%v); want it refused", name, err)
		}
		after, err := book.Query(ctx, Filter{RecordType: RecordTypeDisclosure})
		if err != nil {
			t.Fatal(err)
		}
		if len(after) != len(before) {
			t.Fatalf("%s envelope: a refused bundle committed a disclosure record", name)
		}
	}
}
