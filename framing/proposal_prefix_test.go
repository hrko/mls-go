package framing

import "testing"

func TestProposalPrefixRequiresDeterministicDecoder(t *testing.T) {
	oldProposal, oldCommit := proposalBodyDecoder, commitBodyDecoder
	t.Cleanup(func() { RegisterRawBodyDecoders(oldProposal, oldCommit) })
	wire := NewMLSMessagePublic(&PublicMessage{Content: FramedContent{
		Sender: Sender{Type: SenderTypeExternal}, Body: ProposalBody{Data: []byte{0, 3, 0, 0, 0, 1}},
	}}).Marshal()
	for _, decoder := range []rawBodyDecoder{nil,
		func([]byte) (int, error) { return 0, nil },
		func([]byte) (int, error) { return -1, nil },
		func(b []byte) (int, error) { return len(b) + 1, nil },
	} {
		RegisterRawBodyDecoders(decoder, oldCommit)
		if msg, n, err := UnmarshalMLSProposalPrefix(wire); err == nil || msg != nil || n != 0 {
			t.Fatalf("invalid decoder accepted: n=%d err=%v", n, err)
		}
	}
}
