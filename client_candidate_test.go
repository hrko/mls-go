package mls

import (
	"context"
	"errors"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	"testing"
)

func TestCommitCandidateIsolationAndAdoption(t *testing.T) {
	ctx := context.Background()
	a, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewClient([]byte("bob"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	kp, err := b.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := a.CreateGroup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.ProposeAddMember(ctx, gid, kp); err != nil {
		t.Fatal(err)
	}
	first, err := a.PrepareCommitCandidate(ctx, gid, CommitPendingProposalsOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := a.PrepareCommitCandidate(ctx, gid, CommitPendingProposalsOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	epoch, err := a.Epoch(ctx, gid)
	if err != nil || epoch != 0 {
		t.Fatalf("live epoch %d: %v", epoch, err)
	}
	welcome := second.WelcomeBytes()
	if err = a.AdoptCommitCandidate(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err = a.AdoptCommitCandidate(ctx, first); !errors.Is(err, ErrStaleCommitCandidate) {
		t.Fatalf("stale adoption: %v", err)
	}
	if _, err = b.JoinGroup(ctx, welcome); err != nil {
		t.Fatal(err)
	}
	secretA, err := a.Export(ctx, gid, "candidate-test", nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	secretB, err := b.Export(ctx, gid, "candidate-test", nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	if string(secretA) != string(secretB) {
		t.Fatal("adopted candidate and Welcome disagree")
	}
}

func TestCommitCandidateGuards(t *testing.T) {
	for _, scenario := range []string{"discard", "foreign", "proposal changed", "client closed", "context cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			a, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := NewClient([]byte("bob"), ciphersuite.MLS128DHKEMP256)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			gid, err := a.CreateGroup(ctx)
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := a.PrepareCommitCandidate(ctx, gid, CommitPendingProposalsOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer candidate.Close()
			var got error
			switch scenario {
			case "discard":
				candidate.Close()
				got = a.AdoptCommitCandidate(ctx, candidate)
			case "foreign":
				got = b.AdoptCommitCandidate(ctx, candidate)
			case "proposal changed":
				kp, e := b.FreshKeyPackageBytes(ctx)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = a.ProposeAddMember(ctx, gid, kp); e != nil {
					t.Fatal(e)
				}
				got = a.AdoptCommitCandidate(ctx, candidate)
			case "client closed":
				if err = a.Close(); err != nil {
					t.Fatal(err)
				}
				got = a.AdoptCommitCandidate(ctx, candidate)
			case "context cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				got = a.AdoptCommitCandidate(cancelled, candidate)
			}
			if got == nil {
				t.Fatal("invalid adoption accepted")
			}
			if scenario != "client closed" {
				epoch, e := a.Epoch(ctx, gid)
				if e != nil || epoch != 0 {
					t.Fatalf("epoch changed: %d %v", epoch, e)
				}
			}
		})
	}
}
