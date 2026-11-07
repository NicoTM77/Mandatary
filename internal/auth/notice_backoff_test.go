package auth

import "testing"

func TestNoticeBackoffBounds(t *testing.T) {
	for _, v := range []struct{ attempt, seconds int64 }{{1, 60}, {2, 120}, {3, 240}, {4, 480}, {5, 960}, {6, 1920}, {7, 3600}, {8, 3600}, {0, 3600}, {-1, 3600}, {1 << 62, 3600}} {
		if wait := noticeWait(v.attempt); wait != v.seconds {
			t.Fatal("unsafe/unexpected retry interval", v.attempt, wait)
		}
	}
}
