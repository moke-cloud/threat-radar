package main

import "testing"

func TestLoopbackEndpoint(t *testing.T) {
	ok := []string{"http://127.0.0.1:8080/v1/chat/completions", "http://localhost:8080/v1/chat/completions", "http://[::1]:8080/x"}
	bad := []string{"", "https://models.github.ai/inference/chat/completions", "http://127.0.0.1.evil.com/x", "http://10.0.0.1/x", "file:///etc/passwd"}
	for _, u := range ok {
		if !loopbackEndpoint(u) {
			t.Errorf("%q should be allowed", u)
		}
	}
	for _, u := range bad {
		if loopbackEndpoint(u) {
			t.Errorf("%q should be rejected", u)
		}
	}
}
