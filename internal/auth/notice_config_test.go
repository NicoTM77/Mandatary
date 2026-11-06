package auth

import "testing"

func TestNoticeConfigurationFailsBeforeActivation(t *testing.T) {
	_, repo, _ := serviceFixture(t)
	base := NoticeSettings{Origin: "https://synthetic.example.invalid", Contact: "security@example.invalid", Sender: "notices@example.invalid", Relay: "localhost:465", Mode: "implicit"}
	for _, change := range []func(*NoticeSettings){
		func(n *NoticeSettings) { n.Sender = "notices@example.invalid\r\nBcc: victim@example.invalid" },
		func(n *NoticeSettings) { n.Contact = "" },
		func(n *NoticeSettings) { n.Origin = "http://synthetic.example.invalid" },
		func(n *NoticeSettings) { n.Origin = "https://synthetic.example.invalid/?secret=forbidden" },
		func(n *NoticeSettings) { n.Origin = "https://user@synthetic.example.invalid" },
		func(n *NoticeSettings) { n.Mode = "opportunistic" },
		func(n *NoticeSettings) { n.Relay = "localhost:0" },
		func(n *NoticeSettings) { n.Relay = "localhost:70000" },
		func(n *NoticeSettings) { n.Relay = "localhost:abc" },
		func(n *NoticeSettings) { n.Username = "user" },
		func(n *NoticeSettings) { n.CredentialID = "smtp" },
	} {
		n := base
		change(&n)
		if _, err := NewLifecycle(repo, n); err != ErrDenied {
			t.Fatal("unsafe notice configuration accepted")
		}
	}
}
