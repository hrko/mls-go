package mls

import (
	"bytes"
	"context"
	"errors"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/storage/memory"
	"sync"
	"testing"
)

var errCandidateStore = errors.New("injected candidate save failure")

type candidateFailStore struct {
	*memory.Store
	fail bool
}

func (s *candidateFailStore) SaveGroupState(ctx context.Context, id *group.ID, state []byte) error {
	if s.fail {
		return errCandidateStore
	}
	return s.Store.SaveGroupState(ctx, id, state)
}

func TestCommitCandidateSaveFailureRetry(t *testing.T) {
	for _, cache := range []CacheStrategy{CacheNone, CacheAlways} {
		t.Run(map[CacheStrategy]string{CacheNone: "none", CacheAlways: "always"}[cache], func(t *testing.T) {
			ctx := context.Background()
			store := &candidateFailStore{Store: memory.NewStore()}
			c, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256, WithStorage(store, store), WithCacheStrategy(cache))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			gid, err := c.CreateGroup(ctx)
			if err != nil {
				t.Fatal(err)
			}
			h, err := c.PrepareCommitCandidate(ctx, gid, CommitPendingProposalsOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			before, err := store.LoadGroupState(ctx, group.NewGroupID(gid))
			if err != nil {
				t.Fatal(err)
			}
			store.fail = true
			if err := c.AdoptCommitCandidate(ctx, h); !errors.Is(err, errCandidateStore) {
				t.Fatalf("save error: %v", err)
			}
			after, err := store.LoadGroupState(ctx, group.NewGroupID(gid))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("failed save changed persisted group")
			}
			if epoch, err := c.Epoch(ctx, gid); err != nil || epoch != 0 {
				t.Fatalf("cache advanced on failed save: %d %v", epoch, err)
			}
			store.fail = false
			if err := c.AdoptCommitCandidate(ctx, h); err != nil {
				t.Fatalf("retry: %v", err)
			}
			if epoch, err := c.Epoch(ctx, gid); err != nil || epoch != 1 {
				t.Fatalf("retry did not advance: %d %v", epoch, err)
			}
		})
	}
}

func TestCommitCandidateConcurrentAdoption(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient([]byte("alice"), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	gid, err := c.CreateGroup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var candidates []*CommitCandidate
	for range 2 {
		h, err := c.PrepareCommitCandidate(ctx, gid, CommitPendingProposalsOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		candidates = append(candidates, h)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, h := range candidates {
		wg.Go(func() { <-start; results <- c.AdoptCommitCandidate(ctx, h) })
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrStaleCommitCandidate) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("adopted %d competing candidates", successes)
	}
}
