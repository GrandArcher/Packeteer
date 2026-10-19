package herd

import "testing"

func TestCanonicalOrderAndNumbers(t *testing.T) {
	// Sorted keys, no spaces, and the RFC 8785 number forms.
	in := `{"b": 1.50, "a": [true, null, "x\u000a\"y"], "n": 1e21, "s": 0.0000001, "i": 100, "z": 4.5e-7, "neg": -0.0, "big": 123456789012}`
	got, err := canonicalJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":[true,null,"x\n\"y"],"b":1.5,"big":123456789012,"i":100,"n":1e+21,"neg":0,"s":1e-7,"z":4.5e-7}`
	if string(got) != want {
		t.Fatalf("canonical =\n%s\nwant\n%s", got, want)
	}
}

func TestCanonicalIsIndependentOfInputLayout(t *testing.T) {
	a, _ := canonicalJSON([]byte(`{"x":1,"y":{"q":2,"p":3}}`))
	b, _ := canonicalJSON([]byte("{\n \"y\": {\"p\": 3, \"q\": 2},\n \"x\": 1.0 }"))
	if string(a) != string(b) {
		t.Fatalf("%s != %s", a, b)
	}
}
