package policy

import (
	"strings"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

// srcOf -- источник с одними аргументами строки запроса: value.from почти
// всегда читает именно её.
type argSource struct {
	args    []Pair
	cookies []Pair
}

func (s *argSource) Field(string) string       { return "" }
func (s *argSource) Var(string) (string, bool) { return "", false }
func (s *argSource) Headers() ([]Pair, bool)   { return nil, false }
func (s *argSource) Cookies() ([]Pair, bool)   { return s.cookies, true }
func (s *argSource) Args() ([]Pair, bool)      { return s.args, true }

func cookieOf(t *testing.T, yaml string) *Cookie {
	t.Helper()

	p := parseOne(t, yaml)

	if len(p.Cookies) != 1 {
		t.Fatalf("cookies %d, want 1", len(p.Cookies))
	}

	return p.Cookies[0]
}

const oneCookie = `
cookies:
  - name: waf_src
    max_age: 30d
    value:
      from: $arg_utm_source
      default: direct
      random: 4
rules:
  - issue: waf_src
`

/*
 * Выдача и чтение -- один круг: метка берётся из источника, значение
 * подписывается, и предъявленное читается как своё с той же меткой.
 */
func TestIssueAndRead(t *testing.T) {
	c := cookieOf(t, oneCookie)

	src := &argSource{args: []Pair{{"utm_source", "yandex-direct"}}}
	now := time.Unix(1757232000, 0)

	value, tag, err := c.Issue(src, now, testKey)
	if err != nil {
		t.Fatal(err)
	}

	if tag != "yandex-direct" {
		t.Fatalf("tag %q", tag)
	}

	if !strings.HasPrefix(value, "yandex-direct~") || strings.Count(value, ".") != 2 {
		t.Fatalf("value %q is not <tag>~<rand>.<time>.<mac>", value)
	}

	state, got, err := c.Read(value, now.Add(time.Hour), testKey)
	if err != nil {
		t.Fatal(err)
	}

	if state != StatePresent || got != "yandex-direct" {
		t.Fatalf("read %s/%q, want %s/yandex-direct", state, got, StatePresent)
	}
}

// Источника нет -- метка из default; куки нет -- absent.
func TestIssueDefaultAndAbsent(t *testing.T) {
	c := cookieOf(t, oneCookie)
	now := time.Unix(1757232000, 0)

	_, tag, err := c.Issue(&argSource{}, now, testKey)
	if err != nil {
		t.Fatal(err)
	}

	if tag != "direct" {
		t.Fatalf("tag %q, want direct", tag)
	}

	if state, _, _ := c.Read("", now, testKey); state != StateAbsent {
		t.Fatalf("empty value is %s, want %s", state, StateAbsent)
	}
}

/*
 * Подделка. Правленая метка, чужая подпись, подпись от другой куки и мусор --
 * всё это invalid, и ни одно не «куки нет»: разница между первым визитом и
 * подобранной кукой -- вся суть подписи.
 */
func TestReadInvalid(t *testing.T) {
	c := cookieOf(t, oneCookie)
	now := time.Unix(1757232000, 0)

	value, _, err := c.Issue(&argSource{args: []Pair{{"utm_source", "ads"}}}, now, testKey)
	if err != nil {
		t.Fatal(err)
	}

	other := *c
	other.Name = "waf_ab"

	alien, _, err := other.Issue(&argSource{args: []Pair{{"utm_source", "ads"}}}, now, testKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, raw string }{
		{"tampered tag", "vip" + value[3:]},
		{"tampered mac", value[:len(value)-1] + flip(value[len(value)-1])},
		{"no signature", "ads~00000000"},
		{"garbage", "...."},
		{"another cookie", alien},
		{"future stamp", mustIssue(t, c, now.Add(2*time.Hour))},
	} {
		state, _, err := c.Read(tc.raw, now, testKey)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}

		if state != StateInvalid {
			t.Errorf("%s: %s, want %s (%q)", tc.name, state, StateInvalid, tc.raw)
		}
	}

	// Ключа нет -- это не подделка, а сбой контура.
	if _, _, err := c.Read(value, now, nil); err == nil {
		t.Fatal("a signed cookie without a key must not read as valid")
	}
}

// flip меняет последний знак подписи на заведомо другой.
func flip(c byte) string {
	if c == '0' {
		return "A"
	}

	return "0"
}

func mustIssue(t *testing.T, c *Cookie, now time.Time) string {
	t.Helper()

	v, _, err := c.Issue(&argSource{}, now, testKey)
	if err != nil {
		t.Fatal(err)
	}

	return v
}

// renew_after: до срока -- present, после -- expired, значение при этом целое.
func TestReadExpired(t *testing.T) {
	c := cookieOf(t, `
cookies:
  - name: waf_src
    max_age: 30d
    renew_after: 24h
    value: { default: direct, random: 4 }
rules:
  - issue: waf_src
`)

	issued := time.Unix(1757232000, 0)

	value := mustIssue(t, c, issued)

	if state, _, _ := c.Read(value, issued.Add(23*time.Hour), testKey); state != StatePresent {
		t.Fatalf("before renew_after: %s", state)
	}

	state, tag, _ := c.Read(value, issued.Add(25*time.Hour), testKey)
	if state != StateExpired || tag != "direct" {
		t.Fatalf("after renew_after: %s/%q", state, tag)
	}
}

// Без подписи кука читается как есть: ни времени, ни подделки в ней не видно.
func TestUnsignedCookie(t *testing.T) {
	c := cookieOf(t, `
cookies:
  - name: sid
    sign: none
    value: { from: $cookie_sid, random: 0 }
rules:
  - issue: sid
`)

	if state, tag, _ := c.Read("anything-at-all", time.Now(), nil); state != StatePresent ||
		tag != "anything-at-all" {
		t.Fatalf("unsigned read %s/%q", state, tag)
	}
}

/*
 * Алфавит метки. Значение куки едет в заголовок, в набор и в маркер записи,
 * поэтому всё, что клиент выбрал сам, сводится к [A-Za-z0-9_-] и режется по
 * max_len. Разделители значения (точка и тильда) в метку не проходят.
 */
func TestTagSanitised(t *testing.T) {
	c := cookieOf(t, `
cookies:
  - name: waf_src
    value:
      from: $arg_utm_source
      random: 0
      max_len: 8
rules:
  - issue: waf_src
`)

	_, tag, err := c.Issue(&argSource{args: []Pair{{"utm_source", "a.b~c d;e/f&g"}}},
		time.Now(), testKey)
	if err != nil {
		t.Fatal(err)
	}

	if tag != "a_b_c_d_" {
		t.Fatalf("tag %q", tag)
	}
}

/* --- правила --------------------------------------------------------------- */

const twoRules = `
cookies:
  - name: waf_src
    max_age: 30d
    value: { from: $arg_utm_source, default: direct, random: 4 }
rules:
  - name: first-touch
    on: absent
    issue: waf_src
    actions:
      - do: mark
        marker: "src:{tag}"
  - name: logout
    match: { path_prefix: "/logout" }
    drop: waf_src
    actions:
      - list: ads
        write: cookie
        op: remove
`

// on: absent -- это и есть «первое касание»: правило не срабатывает, когда
// кука уже есть.
func TestCollectOnState(t *testing.T) {
	p := parseOne(t, twoRules)

	out := p.Collect(nil, &Target{Phase: "request", Method: "GET", URI: "/",
		States: map[string]string{"waf_src": StateAbsent}})

	if len(out.Issue) != 1 || out.Issue[0].Name != "waf_src" || len(out.Rules) != 1 {
		t.Fatalf("absent: issue %v, rules %v", out.Issue, out.Rules)
	}

	out = p.Collect(nil, &Target{Phase: "request", Method: "GET", URI: "/",
		States: map[string]string{"waf_src": StatePresent}})

	if len(out.Issue) != 0 || len(out.Rules) != 0 {
		t.Fatalf("present: issue %v, rules %v", out.Issue, out.Rules)
	}
}

// Снятие сильнее выдачи, даже когда правило выдачи стоит первым.
func TestDropBeatsIssue(t *testing.T) {
	p := parseOne(t, twoRules)

	out := p.Collect(nil, &Target{Phase: "request", Method: "GET", URI: "/logout",
		States: map[string]string{"waf_src": StateAbsent}})

	if len(out.Issue) != 0 || len(out.Drop) != 1 {
		t.Fatalf("issue %v, drop %v", out.Issue, out.Drop)
	}

	if len(out.Writes) != 1 || out.Writes[0].Op != OpRemove ||
		out.Writes[0].Subject != WriteCookie || out.Writes[0].Cookie != "waf_src" {
		t.Fatalf("writes %+v", out.Writes)
	}
}

// Фаза правила и код ответа: правило фазы ответа на запросе не срабатывает.
func TestCollectPhaseAndStatus(t *testing.T) {
	p := parseOne(t, `
cookies:
  - name: waf_src
    value: { default: direct, random: 4 }
rules:
  - name: on-200
    phase: response
    status: [200]
    issue: waf_src
`)

	if out := p.Collect(nil, &Target{Phase: "request", Method: "GET", URI: "/"}); len(out.Rules) != 0 {
		t.Fatalf("request phase: %v", out.Rules)
	}

	if out := p.Collect(nil, &Target{Phase: "response", Method: "GET", URI: "/",
		Status: 404}); len(out.Rules) != 0 {
		t.Fatalf("404: %v", out.Rules)
	}

	if out := p.Collect(nil, &Target{Phase: "response", Method: "GET", URI: "/",
		Status: 200}); len(out.Issue) != 1 {
		t.Fatalf("200: %v", out.Rules)
	}
}

/*
 * Отбраковка на загрузке. Каждая строка здесь -- профиль, который иначе
 * работал бы молча неправильно: правило, которое не срабатывает никогда,
 * кука, которую браузер выбросит раньше продления, запись значения куки,
 * которой нет.
 */
func TestProfileRejected(t *testing.T) {
	for _, tc := range []struct{ name, yaml, want string }{
		{"on invalid without signature", `
cookies: [ { name: s, sign: none, value: { random: 4 } } ]
rules: [ { on: invalid, cookie: s, actions: [ { do: score, value: 10, code: A } ] } ]
`, "needs sign"},
		{"on expired without renew_after", `
cookies: [ { name: s, value: { random: 4 } } ]
rules: [ { on: expired, cookie: s, issue: s } ]
`, "needs renew_after"},
		{"renew_after over max_age", `
cookies: [ { name: s, max_age: 1h, renew_after: 2h, value: { random: 4 } } ]
rules: [ { issue: s } ]
`, "not shorter than max_age"},
		{"unknown cookie", `
cookies: [ { name: s, value: { random: 4 } } ]
rules: [ { issue: other } ]
`, "is not declared"},
		{"issue and drop", `
cookies: [ { name: s, value: { random: 4 } } ]
rules: [ { issue: s, drop: s } ]
`, "a rule does one thing"},
		{"status without response phase", `
cookies: [ { name: s, value: { random: 4 } } ]
rules: [ { status: [200], issue: s } ]
`, "status needs phase"},
		{"write cookie without a cookie", `
rules: [ { actions: [ { list: ads, write: cookie, ttl: 1h } ] } ]
`, "needs cookie"},
		{"remove with ttl", `
cookies: [ { name: s, value: { random: 4 } } ]
rules: [ { drop: s, actions: [ { list: ads, write: cookie, op: remove, ttl: 1h } ] } ]
`, "takes no ttl"},
		{"empty value recipe", `
cookies: [ { name: s, value: { random: 0 } } ]
rules: [ { issue: s } ]
`, "value has no source"},
		{"rule does nothing", `
cookies: [ { name: s, value: { random: 4 } } ]
rules: [ { match: { path_prefix: "/x" } } ]
`, "neither issues, drops nor sends"},
		{"cookie declared twice", `
cookies:
  - { name: s, value: { random: 4 } }
  - { name: s, value: { random: 8 } }
rules: [ { issue: s } ]
`, "declared twice"},
		{"on without a name", `
cookies:
  - { name: a, value: { random: 4 } }
  - { name: b, value: { random: 4 } }
rules: [ { on: absent, actions: [ { do: score, value: 10, code: A } ] } ]
`, "needs cookie"},
	} {
		_, err := Parse("default", []byte(tc.yaml))
		if err == nil {
			t.Errorf("%s: profile loaded, expected a refusal", tc.name)

			continue
		}

		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

// Единственная объявленная кука подставляется в правило сама: писать её имя
// в каждой строке незачем.
func TestSingleCookieImplied(t *testing.T) {
	p := parseOne(t, `
cookies: [ { name: s, value: { random: 4 } } ]
rules: [ { on: absent, actions: [ { do: mark, marker: "no-cookie" } ] } ]
`)

	if p.Rules[0].Cookie != "s" {
		t.Fatalf("cookie %q", p.Rules[0].Cookie)
	}

	if !p.NeedsSecret() {
		t.Fatal("a cookie signs by default")
	}
}

/*
 * Снятие куки не должно стирать её значение из того, что известно про запрос:
 * строка op: remove снимает из набора ровно его. Проверяется на форме правила
 * -- сама карта живёт в обработчике, но правило обязано донести до неё и
 * снятие, и набор.
 */
func TestDropCarriesListRemoval(t *testing.T) {
	p := parseOne(t, twoRules)

	out := p.Collect(nil, &Target{Phase: "request", Method: "GET", URI: "/logout",
		States: map[string]string{"waf_src": StatePresent}})

	if len(out.Drop) != 1 || len(out.Writes) != 1 {
		t.Fatalf("drop %v, writes %v", out.Drop, out.Writes)
	}

	w := out.Writes[0]

	if w.Op != OpRemove || w.Subject != WriteCookie || w.Cookie != "waf_src" || w.TTL != 0 {
		t.Fatalf("write %+v", w)
	}
}
