/*
 * Кука: объявление, значение, подпись и состояние на входе.
 *
 * Инспектор держит ровно две операции -- выдать и снять, -- а всё остальное
 * решают правила профиля (policy.go). Здесь живёт то, что знает про саму куку:
 * из чего собрать значение, чем его подписать и что о предъявленном значении
 * можно сказать, не спрашивая никого.
 *
 * Значение устроено так:
 *
 *     <метка>[~<случайное>][.<время>.<подпись>]
 *
 * Метка -- то, ради чего куку заводят: источник перехода, кампания, ветка
 * теста. Она читается глазами и уезжает в маркер записи, поэтому её алфавит
 * узкий: всё, что не [A-Za-z0-9_-], заменяется подчёркиванием. Случайное --
 * уникальность клиента: без неё все пришедшие по одной ссылке неразличимы.
 * Время и подпись -- половина, которую ставит подпись; на них держится и
 * «кука не подделана», и «кука выдана давно».
 *
 * Подпись обязательна по умолчанию и не для красоты. Кука, по которой контур
 * принимает решения -- снять инспектора, пропустить без проверки, посчитать
 * своим, -- без подписи набирается руками в консоли браузера за секунду, и
 * тогда автодействие по ней становится дырой ровно того размера, на который
 * ему дали прав. Ключ -- у процесса (WAF_COOKIE_SECRET), на куку он
 * разводится именем: подпись одной куки не годится для другой.
 */

package policy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Состояние куки на входе: с ним сверяется `on:` правила.
const (
	// StateAbsent -- куки с таким именем клиент не прислал.
	StateAbsent = "absent"
	// StatePresent -- кука есть, и подпись сошлась (либо её не просили).
	StatePresent = "present"
	// StateInvalid -- кука есть, но подпись не сошлась, испорчена форма
	// или время выдачи в будущем. Это не «нет куки»: разница между «клиент
	// пришёл впервые» и «клиенту куку подобрали» -- вся суть подписи.
	StateInvalid = "invalid"
	// StateExpired -- кука своя и целая, но выдана раньше, чем renew_after.
	StateExpired = "expired"
)

// States -- порядок словаря для сообщений об ошибке.
var States = []string{StateAbsent, StatePresent, StateInvalid, StateExpired}

const (
	SignHMAC = "hmac"
	SignNone = "none"
)

const (
	// Предел значения: 256 байт -- столько держит запись набора строк
	// (type=string), а кука, которую нельзя положить в набор, бесполезна
	// ровно там, где куку заводят.
	ValueMax = 256
	// Предел метки до сборки значения; умолчание -- MaxLenDefault.
	MaxLenLimit   = 128
	MaxLenDefault = 64
	// Случайный хвост: байты до шестнадцатеричной записи.
	RandomMax     = 32
	RandomDefault = 8
	// Длина подписи в значении: 12 байт HMAC в base64url -- 16 знаков.
	// Полный SHA-256 здесь не нужен: подделать надо за время жизни куки и
	// вслепую, а каждый лишний знак платится в каждом запросе клиента.
	macBytes = 12
	macChars = 16
)

var cookieNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

/*
 * Recipe -- чем заполнить значение при выдаче. From -- откуда взять метку:
 * любой операнд условий ($arg_utm_source, $http_referer, $cookie_<имя>,
 * $waf_request_args.<имя>). Пусто и там и в Default -- метки нет, значение
 * будет из одного случайного.
 */
type Recipe struct {
	From    *Operand
	Default string
	Random  int
	MaxLen  int
}

/*
 * Cookie -- объявление: имя, атрибуты и способ заполнения. Secure, HttpOnly и
 * SameSite здесь не живут: их форсирует waf_cookie_defaults маршрута, и
 * присланное с провода модуль выбрасывает (docs/verdict-protocol.md,
 * «Ограничения канала»). Домена нет по той же причине -- кука остаётся
 * host-only.
 */
type Cookie struct {
	Name   string
	Path   string
	MaxAge time.Duration
	// MaxAgeSet -- срок назван. Не назван -- кука сессии: Max-Age не едет.
	MaxAgeSet bool
	Sign      string
	// Renew -- возраст, после которого своя кука считается StateExpired.
	// Ноль -- состояния не бывает, и правило с on: expired не грузится.
	Renew time.Duration
	Value Recipe
}

// Signed -- значение подписывается, то есть у него есть время выдачи и
// состояния invalid / expired.
func (c *Cookie) Signed() bool { return c.Sign == SignHMAC }

/*
 * Issue собирает значение. tag возвращается отдельно: он уезжает в маркер
 * записи и в подстановку {tag}, а значение целиком -- клиенту и в набор.
 *
 * avail=false у операнда (объект обменника недоступен) значением не считается:
 * метка берётся из Default. Молча выдать куку с пустой меткой хуже -- по ней
 * потом нечего считать, а понять, что источник не доехал, уже не по чему.
 */
func (c *Cookie) Issue(src Source, now time.Time, key []byte) (value, tag string, err error) {
	raw := c.Value.Default

	if c.Value.From != nil {
		if values, avail := c.Value.From.Values(src); avail && len(values) > 0 && values[0] != "" {
			raw = values[0]
		}
	}

	limit := c.Value.MaxLen
	if limit <= 0 {
		limit = MaxLenDefault
	}

	tag = sanitizeTag(raw, limit)

	var sb strings.Builder

	sb.WriteString(tag)

	if c.Value.Random > 0 {
		buf := make([]byte, c.Value.Random)

		if _, err := rand.Read(buf); err != nil {
			return "", "", fmt.Errorf("random for cookie %q: %w", c.Name, err)
		}

		if tag != "" {
			sb.WriteByte('~')
		}

		sb.WriteString(hex.EncodeToString(buf))
	}

	value = sb.String()

	if value == "" {
		return "", "", fmt.Errorf("cookie %q: value recipe yields nothing", c.Name)
	}

	if c.Signed() {
		if len(key) == 0 {
			return "", "", ErrNoSecret
		}

		stamp := strconv.FormatInt(now.Unix(), 36)
		value = value + "." + stamp + "." + mac(key, c.Name, value+"."+stamp)
	}

	if len(value) > ValueMax {
		return "", "", fmt.Errorf("cookie %q: value is %d bytes, over %d",
			c.Name, len(value), ValueMax)
	}

	return value, tag, nil
}

/*
 * Read отвечает, что предъявил клиент. raw -- значение куки как пришло;
 * пустая строка означает, что куки не было (пустая кука -- тоже её
 * отсутствие: так выглядит снятая в прошлом ответе).
 *
 * Ключа нет, а подпись объявлена -- это не invalid: ошибка в контуре, а не у
 * клиента, и обвинять его в ней нельзя. Такой случай возвращает ErrNoSecret, и
 * инспектор отвечает error, как при молчащем кодере гео.
 */
func (c *Cookie) Read(raw string, now time.Time, key []byte) (state, tag string, err error) {
	if raw == "" {
		return StateAbsent, "", nil
	}

	if len(raw) > ValueMax {
		return StateInvalid, "", nil
	}

	if !c.Signed() {
		return StatePresent, tagOf(raw), nil
	}

	if len(key) == 0 {
		return "", "", ErrNoSecret
	}

	// Разбор справа: метка живёт в алфавите без точек, поэтому последние два
	// поля -- всегда время и подпись.
	rest, sig, ok := cutLast(raw, '.')
	if !ok {
		return StateInvalid, "", nil
	}

	payload, stamp, ok := cutLast(rest, '.')
	if !ok {
		return StateInvalid, "", nil
	}

	if len(sig) != macChars ||
		subtle.ConstantTimeCompare([]byte(sig), []byte(mac(key, c.Name, payload+"."+stamp))) != 1 {
		return StateInvalid, "", nil
	}

	secs, perr := strconv.ParseInt(stamp, 36, 64)
	if perr != nil {
		return StateInvalid, "", nil
	}

	issued := time.Unix(secs, 0)

	/*
	 * Время выдачи в будущем -- подписанная нами кука с чужими часами либо
	 * переставленное время на ноде. Минута допуска: расхождение часов внутри
	 * контура меньше неё, а больше -- уже повод не доверять штампу.
	 */
	if issued.After(now.Add(time.Minute)) {
		return StateInvalid, "", nil
	}

	if c.Renew > 0 && now.Sub(issued) >= c.Renew {
		return StateExpired, tagOf(payload), nil
	}

	return StatePresent, tagOf(payload), nil
}

// ErrNoSecret -- подпись объявлена, а ключа у процесса нет. Отдельной ошибкой,
// а не состоянием куки: это сбой контура, и отвечать на него надо error.
var ErrNoSecret = fmt.Errorf("cookie signing key is not configured")

/*
 * mac -- подпись значения. Ключ разводится именем куки: одна и та же строка
 * под именем waf_src и waf_ab не должна подходить к обеим, иначе значение,
 * законно выданное для одной, предъявляется вместо другой.
 */
func mac(key []byte, name, payload string) string {
	derived := hmac.New(sha256.New, key)
	derived.Write([]byte("cookie:" + name))

	h := hmac.New(sha256.New, derived.Sum(nil))
	h.Write([]byte(payload))

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:macBytes])[:macChars]
}

// tagOf -- метка предъявленного значения: всё до случайного хвоста.
func tagOf(payload string) string {
	if i := strings.IndexByte(payload, '~'); i >= 0 {
		return payload[:i]
	}

	return payload
}

// cutLast режет по последнему разделителю: значение разбирается справа.
func cutLast(s string, sep byte) (head, tail string, ok bool) {
	i := strings.LastIndexByte(s, sep)
	if i < 0 {
		return "", "", false
	}

	return s[:i], s[i+1:], true
}

/*
 * sanitizeTag -- алфавит метки. Всё, что не [A-Za-z0-9_-], становится
 * подчёркиванием: значение куки едет в заголовок ответа, в набор и в маркер
 * записи, и байт из строки запроса, который клиент выбрал сам, не должен
 * определять, чем это окажется на той стороне. Точка и тильда выброшены
 * отдельно -- ими разбирается само значение.
 */
func sanitizeTag(raw string, limit int) string {
	if raw == "" {
		return ""
	}

	if limit > MaxLenLimit {
		limit = MaxLenLimit
	}

	out := make([]byte, 0, limit)

	for i := 0; i < len(raw) && len(out) < limit; i++ {
		c := raw[i]

		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '-':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}

	return string(out)
}

/* --- разбор объявления ----------------------------------------------------- */

type fileRecipe struct {
	From    string `yaml:"from"`
	Default string `yaml:"default"`
	Random  *int   `yaml:"random"`
	MaxLen  int    `yaml:"max_len"`
}

type fileCookie struct {
	Name   string      `yaml:"name"`
	Path   string      `yaml:"path"`
	MaxAge string      `yaml:"max_age"`
	Sign   string      `yaml:"sign"`
	Renew  string      `yaml:"renew_after"`
	Value  *fileRecipe `yaml:"value"`
}

func parseCookie(at string, fc fileCookie) (*Cookie, error) {
	c := &Cookie{
		Name: strings.TrimSpace(fc.Name),
		Path: strings.TrimSpace(fc.Path),
		Sign: strings.TrimSpace(fc.Sign),
	}

	if !cookieNameRe.MatchString(c.Name) {
		return nil, fmt.Errorf("%s: name %q is not a cookie name", at, c.Name)
	}

	if c.Path == "" {
		c.Path = "/"
	}

	if !strings.HasPrefix(c.Path, "/") {
		return nil, fmt.Errorf("%s: path %q does not start with /", at, c.Path)
	}

	if c.Sign == "" {
		c.Sign = SignHMAC
	}

	if c.Sign != SignHMAC && c.Sign != SignNone {
		return nil, fmt.Errorf("%s: sign must be %s or %s, got %q",
			at, SignHMAC, SignNone, c.Sign)
	}

	if s := strings.TrimSpace(fc.MaxAge); s != "" {
		d, err := parseTTL(s)
		if err != nil {
			return nil, fmt.Errorf("%s: max_age: %w", at, err)
		}

		if d < time.Second {
			return nil, fmt.Errorf("%s: max_age %q is shorter than a second", at, s)
		}

		c.MaxAge, c.MaxAgeSet = d, true
	}

	if s := strings.TrimSpace(fc.Renew); s != "" {
		d, err := parseTTL(s)
		if err != nil {
			return nil, fmt.Errorf("%s: renew_after: %w", at, err)
		}

		if d < time.Second {
			return nil, fmt.Errorf("%s: renew_after %q is shorter than a second", at, s)
		}

		if c.Sign != SignHMAC {
			return nil, fmt.Errorf("%s: renew_after needs sign: %s -- "+
				"without a signature the cookie carries no issue time", at, SignHMAC)
		}

		if c.MaxAgeSet && d >= c.MaxAge {
			return nil, fmt.Errorf("%s: renew_after %q is not shorter than max_age -- "+
				"the browser drops the cookie before it is renewed", at, s)
		}

		c.Renew = d
	}

	rec := fileRecipe{}
	if fc.Value != nil {
		rec = *fc.Value
	}

	if s := strings.TrimSpace(rec.From); s != "" {
		op, err := ParseOperand(s)
		if err != nil {
			return nil, fmt.Errorf("%s: value.from: %w", at, err)
		}

		c.Value.From = &op
	}

	c.Value.Default = sanitizeTag(strings.TrimSpace(rec.Default), MaxLenLimit)

	c.Value.Random = RandomDefault
	if rec.Random != nil {
		c.Value.Random = *rec.Random
	}

	if c.Value.Random < 0 || c.Value.Random > RandomMax {
		return nil, fmt.Errorf("%s: value.random must be within 0..%d, got %d",
			at, RandomMax, c.Value.Random)
	}

	c.Value.MaxLen = rec.MaxLen
	if c.Value.MaxLen == 0 {
		c.Value.MaxLen = MaxLenDefault
	}

	if c.Value.MaxLen < 1 || c.Value.MaxLen > MaxLenLimit {
		return nil, fmt.Errorf("%s: value.max_len must be within 1..%d, got %d",
			at, MaxLenLimit, c.Value.MaxLen)
	}

	/*
	 * Значение, которого не бывает: ни источника, ни умолчания, ни
	 * случайного. Кука с пустым значением -- это снятая кука, и выдавать её
	 * выдачей нельзя.
	 */
	if c.Value.From == nil && c.Value.Default == "" && c.Value.Random == 0 {
		return nil, fmt.Errorf("%s: value has no source: set from, default or random", at)
	}

	return c, nil
}
