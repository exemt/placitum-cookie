package policy

import "testing"

func TestOverloadRule(t *testing.T) {
	p, err := Parse("p", []byte("rules:\n"+
		"  - on: overload\n    at: 60\n    actions:\n      - { list: hot, ttl: 10m }\n"))
	if err != nil {
		t.Fatal(err)
	}

	// Обычный проход строку перегрузки не видит.
	if out := p.Collect(nil, &Target{Phase: "request", Method: "GET", URI: "/"}); len(out.Writes) != 0 {
		t.Fatalf("collect: %+v", out.Writes)
	}

	if out := p.CollectOverload(59, false); len(out.Writes) != 0 {
		t.Fatalf("below the threshold: %+v", out.Writes)
	}

	if out := p.CollectOverload(60, false); len(out.Writes) != 1 {
		t.Fatalf("at the threshold: %+v", out.Writes)
	}

	if out := p.CollectOverload(100, true); len(out.Writes) != 1 {
		t.Fatalf("shed: %+v", out.Writes)
	}

	for name, body := range map[string]string{
		"under the scale": "rules:\n  - on: overload\n    at: 10\n    actions:\n      - { list: hot, ttl: 10m }\n",
		"with a phase":    "rules:\n  - on: overload\n    phase: request\n    actions:\n      - { list: hot, ttl: 10m }\n",
		"without actions": "rules:\n  - on: overload\n    at: 60\n",
		"at without on":   "rules:\n  - at: 60\n    actions:\n      - { list: hot, ttl: 10m }\n",
	} {
		if _, err := Parse("p", []byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
