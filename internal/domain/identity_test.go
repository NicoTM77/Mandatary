package domain

import "testing"

func TestEndpointID(t *testing.T) {
	const valid = "63cd757e-a443-4dd6-97b0-29087e5eaab9"
	id, err := ParseEndpointID(valid)
	if err != nil || string(id) != valid {
		t.Fatalf("canonical UUID rejected: %v", err)
	}
	for _, value := range []string{"", "local", "00000000-0000-0000-0000-000000000000", "63CD757E-a443-4dd6-97b0-29087e5eaab9", "63cd757e-a443-4dd6-97b0-29087e5eaabz", "63cd757e-a4434-dd6-97b0-29087e5eaab9"} {
		if _, err := ParseEndpointID(value); err == nil {
			t.Errorf("invalid endpoint ID accepted: %q", value)
		}
	}
	first, err := NewEndpointID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewEndpointID()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("UUIDs repeated")
	}
	if _, err := ParseEndpointID(string(first)); err != nil {
		t.Fatal(err)
	}
}
