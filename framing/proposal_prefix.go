package framing

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/internal/tls"
	"github.com/thomas-vilte/mls-go/keypackages"
)

// UnmarshalMLSProposalPrefix parses one public Proposal MLSMessage at the start
// of data and returns its exact wire length. Remaining bytes are not inspected.
// On error, it returns a nil message and zero consumed bytes.
//
// A deterministic proposal body decoder must be registered (the group package
// registers one during initialization). There is deliberately no boundary scan
// fallback. Other content types and wire formats are rejected. Existing complete
// message parsers retain their behavior.
//
// This parses framing only: callers must still verify signatures, membership
// tags, group/epoch, proposal semantics, and authorization before accepting it.
func UnmarshalMLSProposalPrefix(data []byte) (*MLSMessage, int, error) {
	r := tls.NewReader(data)
	version, err := r.ReadUint16()
	if err != nil {
		return nil, 0, fmt.Errorf("framing: reading version: %w", err)
	}
	if keypackages.ProtocolVersion(version) != keypackages.MLS10 {
		return nil, 0, fmt.Errorf("%w: unsupported protocol version %d", ErrInvalidMessage, version)
	}
	wf, err := r.ReadUint16()
	if err != nil {
		return nil, 0, fmt.Errorf("framing: reading wire_format: %w", err)
	}
	if WireFormat(wf) != WireFormatPublicMessage {
		return nil, 0, fmt.Errorf("%w: expected public proposal, got %d", ErrInvalidWireFormat, wf)
	}
	content, err := unmarshalFramedContentWithBodyReader(r, readProposalPrefixBody)
	if err != nil {
		return nil, 0, err
	}
	sig, err := r.ReadVLBytes()
	if err != nil {
		return nil, 0, fmt.Errorf("framing: reading signature: %w", err)
	}
	pm := &PublicMessage{Content: *content, Auth: FramedContentAuthData{Signature: ciphersuite.NewSignature(sig)}}
	if content.Sender.Type == SenderTypeMember {
		pm.MembershipTag, err = r.ReadVLBytes()
		if err != nil {
			return nil, 0, fmt.Errorf("framing: reading membership_tag: %w", err)
		}
	}
	return NewMLSMessagePublic(pm), r.Position(), nil
}

func readProposalPrefixBody(r *tls.Reader, ct ContentType, sender SenderType) (FramedContentBody, error) {
	if ct != ContentTypeProposal {
		return nil, fmt.Errorf("%w: expected proposal, got %d", ErrInvalidContentType, ct)
	}
	if err := ValidateSenderContentType(sender, ct); err != nil {
		return nil, err
	}
	if proposalBodyDecoder == nil {
		return nil, fmt.Errorf("framing: proposal prefix requires a registered body decoder")
	}
	remaining := r.BytesAfterPosition()
	n, err := proposalBodyDecoder(remaining)
	if err != nil {
		return nil, fmt.Errorf("framing: reading proposal body: %w", err)
	}
	if n <= 0 || n > len(remaining) {
		return nil, fmt.Errorf("framing: invalid proposal body length %d", n)
	}
	body := append([]byte(nil), remaining[:n]...)
	r.Skip(n)
	return ProposalBody{Data: body}, nil
}
