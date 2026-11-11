package group

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
)

func prefixRemove(sender framing.SenderType) []byte {
	pm := &framing.PublicMessage{
		Content: framing.FramedContent{
			GroupID: []byte("group"), Epoch: 7,
			Sender: framing.Sender{Type: sender},
			Body:   framing.ProposalBody{Data: []byte{0, 3, 0, 0, 0, 1}},
		},
		Auth: framing.FramedContentAuthData{Signature: ciphersuite.NewSignature(bytes.Repeat([]byte{42}, 64))},
	}
	if sender == framing.SenderTypeMember {
		pm.MembershipTag = bytes.Repeat([]byte{7}, 32)
	}
	return framing.NewMLSMessagePublic(pm).Marshal()
}

func TestMLSProposalPrefix(t *testing.T) {
	for _, sender := range []framing.SenderType{framing.SenderTypeExternal, framing.SenderTypeMember, framing.SenderTypeNewMemberProposal} {
		wire := prefixRemove(sender)
		batch := append(append([]byte(nil), wire...), wire...)
		for i := 0; i < 2; i++ {
			msg, n, err := framing.UnmarshalMLSProposalPrefix(batch)
			if err != nil || n != len(wire) || !bytes.Equal(msg.Marshal(), wire) {
				t.Fatalf("sender=%d item=%d: n=%d err=%v", sender, i, n, err)
			}
			batch = batch[n:]
		}
		// Every truncation of the first message must fail without reporting consumption.
		for end := 0; end < len(wire); end++ {
			msg, n, err := framing.UnmarshalMLSProposalPrefix(wire[:end])
			if err == nil || n != 0 || msg != nil {
				t.Fatalf("sender=%d truncation=%d: n=%d err=%v", sender, end, n, err)
			}
		}
		if _, err := framing.UnmarshalMLSMessage(append(append([]byte(nil), wire...), wire...)); err == nil {
			t.Fatal("complete-message parser unexpectedly accepted a batch")
		}
	}
}

func TestMLSProposalPrefixRejectsOtherMessages(t *testing.T) {
	for _, mutation := range []func([]byte){
		func(b []byte) { b[1] = 2 }, // version
		func(b []byte) { b[3] = byte(framing.WireFormatPrivateMessage) },
		func(b []byte) { b[18] = 0 }, // reserved sender
		func(b []byte) { b[24] = byte(framing.ContentTypeCommit) },
		func(b []byte) { b[26] = 255 }, // unknown proposal
	} {
		wire := prefixRemove(framing.SenderTypeExternal)
		mutation(wire)
		if msg, n, err := framing.UnmarshalMLSProposalPrefix(wire); err == nil || msg != nil || n != 0 {
			t.Fatalf("accepted invalid message: n=%d err=%v", n, err)
		}
	}
}

func TestMLSProposalPrefixInteropVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/mls-interop-testvectors/test-vectors/passive-client-handling-commit.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []passiveClientCommitVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, v := range vectors {
		if !ciphersuite.CipherSuite(v.CipherSuite).IsSupported() {
			continue
		}
		for _, epoch := range v.Epochs {
			for _, encoded := range epoch.Proposals {
				wire := mustDecodeHex(t, encoded)
				batch := append(append([]byte(nil), wire...), wire...)
				msg, n, err := framing.UnmarshalMLSProposalPrefix(batch)
				if err != nil || n != len(wire) || !bytes.Equal(msg.Marshal(), wire) {
					t.Fatalf("vector prefix: n=%d want=%d err=%v", n, len(wire), err)
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("no proposals checked")
	}
}

func FuzzMLSProposalPrefix(f *testing.F) {
	wire := prefixRemove(framing.SenderTypeExternal)
	f.Add(wire)
	f.Add(append(append([]byte(nil), wire...), wire...))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, n, err := framing.UnmarshalMLSProposalPrefix(data)
		if err != nil {
			if msg != nil || n != 0 {
				t.Fatal("partial result on failure")
			}
			return
		}
		if msg == nil || n <= 0 || n > len(data) {
			t.Fatal("invalid consumed length")
		}
		// A prefix must also be a complete message by the existing parser.
		if _, err := framing.UnmarshalMLSMessage(data[:n]); err != nil {
			t.Fatal(err)
		}
		_, again, err := framing.UnmarshalMLSProposalPrefix(data[:n])
		if err != nil || again != n {
			t.Fatalf("unstable boundary: %d %v", again, err)
		}
	})
}
