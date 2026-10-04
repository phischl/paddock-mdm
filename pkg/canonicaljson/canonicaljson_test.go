package canonicaljson

import "testing"

// Vectors from RFC 8785 §3.2.2–§3.2.3 and appendix B.
func TestTransformVectors(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"whitespace and order", `{ "b" : 2 , "a" : [ 1 , true , null ] }`, `{"a":[1,true,null],"b":2}`},
		{"numbers", `{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]}`,
			`{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}`},
		{"literals and string escapes", `{"literals":[null,true,false],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/"}`,
			`{"literals":[null,true,false],"string":"€$\u000f\nA'B\"\\\\\"/"}`},
		{"sorting by UTF-16 code units", `{"\u20ac":"Euro Sign","\r":"Carriage Return","\ud83d\ude00":"Emoji: Grinning Face","1":"One","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis","\ufb33":"Hebrew Letter Dalet With Dagesh"}`,
			"{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"},
		{"nested objects", `{"z":{"y":1,"x":2},"a":[]}`, `{"a":[],"z":{"x":2,"y":1}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Transform([]byte(c.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("got  %s\nwant %s", got, c.want)
			}
		})
	}
}

func TestTransformRejectsInvalidJSON(t *testing.T) {
	for _, in := range []string{``, `{`, `{"a":1,}`, `[1 2]`} {
		if _, err := Transform([]byte(in)); err == nil {
			t.Errorf("Transform(%q) succeeded", in)
		}
	}
}

func TestMarshal(t *testing.T) {
	got, err := Marshal(struct {
		B int    `json:"b"`
		A string `json:"a"`
	}{B: 1, A: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":"x","b":1}` {
		t.Fatalf("got %s", got)
	}
}
