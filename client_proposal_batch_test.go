package mls

import (
	"bytes"
	"context"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	memory "github.com/thomas-vilte/mls-go/storage/memory"
	"testing"
)

func TestProposalBatchAtomicRejection(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	a, err := NewClient([]byte("a"), ciphersuite.MLS128DHKEMP256, WithStorage(store, store))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewClient([]byte("b"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	gid, err := a.CreateGroup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := b.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := a.ProposeAddMember(ctx, gid, kp)
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.LoadGroupState(ctx, group.NewGroupID(gid))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		messages, refs [][]byte
	}{
		{name: "duplicate", messages: [][]byte{wire}},
		{name: "malformed", messages: [][]byte{{0}}},
		{name: "unknown revoke", refs: [][]byte{make([]byte, 32)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := a.ApplyProposalBatch(ctx, gid, tc.messages, tc.refs); err == nil {
				t.Fatal("invalid batch accepted")
			}
			after, err := store.LoadGroupState(ctx, group.NewGroupID(gid))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("failed batch changed persisted state")
			}
		})
	}
}
