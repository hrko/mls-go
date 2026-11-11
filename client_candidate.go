package mls

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// ErrStaleCommitCandidate means the source state changed after preparation.
var ErrStaleCommitCandidate = errors.New("commit candidate no longer matches group state")

// CommitCandidate owns serialized private group state. Call Close after use.
// Preparing it does not advance or pin the live group, and produces Welcome
// immediately for delivery protocols which submit Commit and Welcome together.
type CommitCandidate struct {
	mu                                   sync.Mutex
	owner                                *Client
	groupID, base, next, commit, welcome []byte
	closed                               bool
}

func (h *CommitCandidate) CommitBytes() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return cloneBytes(h.commit)
}
func (h *CommitCandidate) WelcomeBytes() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return cloneBytes(h.welcome)
}
func (h *CommitCandidate) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	clear(h.base)
	clear(h.next)
	h.base = nil
	h.next = nil
	h.commit = nil
	h.welcome = nil
	h.owner = nil
	h.closed = true
}

// PrepareCommitCandidate signs with this client's identity but performs every
// group mutation on a deserialized copy. No events or storage writes occur.
func (c *Client) PrepareCommitCandidate(ctx context.Context, gid []byte, opts CommitPendingProposalsOptions) (*CommitCandidate, error) {
	entry, g, err := c.lockGroup(ctx, gid)
	if err != nil {
		return nil, err
	}
	defer entry.mu.Unlock()
	base, err := g.MarshalState()
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			clear(base)
		}
	}()
	isolated, err := group.UnmarshalGroupState(base)
	if err != nil {
		return nil, err
	}
	if err = c.reviewStoredProposals(ctx, isolated); err != nil {
		return nil, err
	}
	staged, err := isolated.Commit(c.sigKey, c.sigKey.PublicKey(), nil)
	if err != nil {
		return nil, err
	}
	commit := framing.NewMLSMessagePublic(&framing.PublicMessage{Content: staged.AuthenticatedContent().Content, Auth: staged.AuthenticatedContent().Auth, MembershipTag: staged.MembershipTag()}).Marshal()
	var kps []*keypackages.KeyPackage
	for _, p := range staged.Proposals() {
		if p.Type == group.ProposalTypeAdd && p.Add != nil {
			kps = append(kps, p.Add.KeyPackage)
		}
	}
	if err = isolated.MergeCommit(staged); err != nil {
		return nil, err
	}
	var welcome []byte
	if len(kps) > 0 {
		options := []group.CreateWelcomeOption{group.WithJoinerSecret(staged.JoinerSecret()), group.WithPSKIDs(staged.PskIDs()), group.WithPSKSecret(staged.RawPskSecret()), group.WithStagedCommit(staged)}
		if info := commitPendingOptionsForCommit(opts); len(info) > 0 {
			options = append(options, group.WithGroupInfoOptions(info...))
		}
		w, e := isolated.CreateWelcomeWithOpts(kps, c.sigKey, options...)
		if e != nil {
			return nil, e
		}
		welcome = (&framing.MLSMessage{Welcome: w.Marshal()}).Marshal()
	}
	next, err := isolated.MarshalState()
	if err != nil {
		return nil, err
	}
	success = true
	return &CommitCandidate{owner: c, groupID: cloneBytes(gid), base: base, next: next, commit: commit, welcome: welcome}, nil
}

// AdoptCommitCandidate accepts only a candidate made from the exact current
// state. DAVE-specific proposal and participant validation remains the caller's
// responsibility. Adoption does not send messages or switch media keys.
func (c *Client) AdoptCommitCandidate(ctx context.Context, h *CommitCandidate) error {
	if h == nil {
		return ErrStaleCommitCandidate
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.owner != c {
		return ErrStaleCommitCandidate
	}
	entry, g, err := c.lockGroup(ctx, h.groupID)
	if err != nil {
		return err
	}
	defer entry.mu.Unlock()
	current, err := g.MarshalState()
	if err != nil {
		return err
	}
	defer clear(current)
	if !bytes.Equal(current, h.base) {
		return ErrStaleCommitCandidate
	}
	next, err := group.UnmarshalGroupState(h.next)
	if err != nil {
		return err
	}
	if err = c.persistGroup(ctx, next, entry); err != nil {
		return err
	}
	clear(h.base)
	clear(h.next)
	h.base = nil
	h.next = nil
	h.closed = true
	h.owner = nil
	return nil
}
