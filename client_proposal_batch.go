package mls

import (
	"context"
	"fmt"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
)

// ApplyProposalBatch validates an append or revoke batch against a private copy.
// Unknown/repeated revocations and duplicate proposals reject the entire batch.
// Callers must not supply both appends and revocations. Persistence uses the
// normal store contract; parsing/authentication/policy failures never write it.
func (c *Client) ApplyProposalBatch(ctx context.Context, gid []byte, messages [][]byte, refs [][]byte) error {
	if len(messages) > 0 && len(refs) > 0 {
		return fmt.Errorf("mixed append and revoke batch")
	}
	entry, g, err := c.lockGroup(ctx, gid)
	if err != nil {
		return err
	}
	defer entry.mu.Unlock()
	raw, err := g.MarshalState()
	if err != nil {
		return err
	}
	defer clear(raw)
	working, err := group.UnmarshalGroupState(raw)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, p := range working.StoredProposals() {
		if known[string(p.Ref)] {
			return fmt.Errorf("duplicate stored proposal")
		}
		known[string(p.Ref)] = true
	}
	for _, ref := range refs {
		if !known[string(ref)] {
			return fmt.Errorf("unknown or repeated revoked proposal")
		}
		delete(known, string(ref))
		if !working.RevokeProposal(ref) {
			return fmt.Errorf("proposal revocation failed")
		}
	}
	for _, wire := range messages {
		if err = ctx.Err(); err != nil {
			return err
		}
		msg, e := framing.UnmarshalMLSMessage(wire)
		if e != nil {
			return e
		}
		pub, ok := msg.AsPublic()
		if !ok || pub.Content.ContentType() != framing.ContentTypeProposal {
			return ErrUnexpectedMessageType
		}
		ac := &framing.AuthenticatedContent{WireFormat: framing.WireFormatPublicMessage, Content: pub.Content, Auth: pub.Auth}
		ref := group.ComputeProposalRef(ac.Marshal(), working.CipherSuite())
		if known[string(ref)] {
			return fmt.Errorf("duplicate proposal reference")
		}
		if err = working.ProcessPublicMessage(pub); err != nil {
			return err
		}
		reviewable, e := c.reviewableProposalFromPublicMessage(working, pub)
		if e != nil {
			return e
		}
		if err = c.reviewProposal(ctx, working, reviewable); err != nil {
			return err
		}
		known[string(ref)] = true
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return c.persistGroup(ctx, working, entry)
}
