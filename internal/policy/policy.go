/*
 * Профили инспектора куки.
 *
 * Профиль устроен в два уровня, и это не украшение. Объявление (cookies:)
 * говорит, что это за кука: имя, срок, чем заполняется значение и чем оно
 * подписывается, -- и живёт дольше любого запроса. Правило (rules:) говорит,
 * когда её выдать или снять и о чём при этом рассказать соседям. Так «первое
 * касание» и «последнее касание» перестают быть настройкой с двумя значениями
 * и становятся видимой разницей: правило с on: absent выдаёт только тому, у
 * кого куки нет, правило без on: -- каждому.
 *
 * Ничего не проверяется и никто не блокируется: вердикт всегда allow. Инспектор
 * ставит куку, пишет её значение в живые наборы и рассказывает соседям
 * действиями канала docs/inspector-actions.md -- так же, как инспектор
 * действий, с которого этот скелет и снят.
 *
 * Правила накопительные, терминальных нет: срабатывают все совпавшие, действия
 * складываются в порядке правил. Порядок строк -- порядок отправки, а предел
 * количества держит модуль (waf_actions_max). Спор за саму куку решается не
 * порядком: снятие сильнее выдачи.
 *
 * Валидация повторяет отбраковку модуля: несовпадение глагола и оси, числа вне
 * диапазона, кривой повод стоили бы на проводе всего ответа, поэтому такой
 * профиль не грузится вовсе. Сюда же добавлено то, что модуль проверить не
 * может: правило с on: invalid у неподписанной куки не срабатывает никогда, и
 * находиться это должно на загрузке, а не в отчёте «почему не работает».
 */

package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-cookie/internal/protocol"
)

const DefaultName = "default"

const (
	ModeEnforce = "enforce"
	ModeOff     = "off"
)

/*
 * Кого писать в набор -- те же слова, что у остальных отправителей: адрес
 * клиента либо то, во что он разворачивается у кодера гео (netinfo.Values):
 * net -- эффективный анонс, самый узкий; net_all -- все анонсы, накрывающие
 * адрес, включая чужие широкие; asn -- состав системы эффективного анонса.
 */
const (
	WriteAddr   = "addr"
	WriteNet    = "net"
	WriteNetAll = "net_all"
	WriteASN    = "asn"
	/*
	 * WriteCookie -- пятый вид, и он есть только здесь: в набор уезжает
	 * значение самой куки, а не то, с какого адреса её предъявили. Ради
	 * него набор и заводится -- край сверяет его быстрым путём
	 * (waf_local_check <набор> $waf_request_cookies.<имя>), не спрашивая
	 * шину. Набор под такую запись -- type=string, и почти всегда с
	 * hash=md5: значение куки в shm открытым текстом не лежит.
	 */
	WriteCookie = "cookie"
)

// Операция записи: положить в набор либо снять из него. Снятие -- половина
// пары к выдаче: сняли куку -- убрали клиента из набора, который её признавал.
const (
	OpAdd    = "add"
	OpRemove = "remove"
)

// DefaultWriteReason -- повод записи в набор, когда строка своего не назвала.
const DefaultWriteReason = "COOKIE_LIST"

/*
 * Глаголы словаря и допустимые для каждого оси -- копия реестра контроллера
 * (controller/src/model/actions.ts). Инспектор действие не толкует, он только
 * не даёт собрать то, чего модуль всё равно не пропустит.
 */
var verbs = map[string][]string{
	protocol.DoChallenge: {protocol.ApplyRequest},
	protocol.DoThreshold: {protocol.ApplyRequest},
	protocol.DoSkip:      {protocol.ApplyRequest},
	protocol.DoReauth:    {protocol.ApplySession},
	protocol.DoNote: {
		protocol.ApplyRequest, protocol.ApplyIP, protocol.ApplyASN, protocol.ApplySession,
	},
	protocol.DoMutate:  {protocol.ApplyRequest},
	protocol.DoActive:  {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoPassive: {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoOff:     {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoVote:    {protocol.ApplyRequest, protocol.ApplyConn},
	// Глаголы записи: журнал и архив этого запроса. Исполняет модуль от
	// любого спрошенного инспектора; адресата нет.
	protocol.DoAudit:   {protocol.ApplyRequest, protocol.ApplyResponse},
	protocol.DoArchive: {protocol.ApplyRequest, protocol.ApplyResponse},
	// Маркер: метка события на записи. Адресат тот же -- запись маршрута, --
	// но грант ему не нужен: метка ничего не прячет.
	protocol.DoMark: {protocol.ApplyRequest},
	// Очки на маршруте: value со знаком к сумме фазы, исполняет модуль;
	// адресат -- сумма самого маршрута, поля to нет.
	protocol.DoScore: {protocol.ApplyRequest},
}

// auditVerb -- глагол записи: исполняет модуль в адрес записи маршрута,
// поля to нет; сторона set обязательна, срок, предел и набор объектов --
// только у archive с set on.
func auditVerb(do string) bool {
	return do == protocol.DoAudit || do == protocol.DoArchive
}

/*
 * recordVerb -- адресат глагола не сосед, а запись самого маршрута: журнал,
 * архив и маркер. Поля to у них нет.
 */
func recordVerb(do string) bool {
	return auditVerb(do) || do == protocol.DoMark || do == protocol.DoScore
}

// archiveObject -- объект обменника, который умеет назвать archive.
func archiveObject(name string) bool {
	return name == "headers" || name == "args" || name == "body"
}

// Повод: то же ограничение, которым модуль отбраковывает действие с провода.
var codeRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// Имя корзины у note: алфавит имён счётчиков получателя, модульная форма та же.
var counterRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

/*
 * Статика по расширению. Список нарочно короткий и без картинок-приманок вроде
 * .php: он отвечает на вопрос "похоже ли это на подгрузку ресурсов страницы
 * живым браузером", а не классифицирует контент. Уточняется suffixes правила.
 */
var staticSuffixes = []string{
	".css", ".js", ".mjs", ".map",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
	".woff", ".woff2", ".ttf", ".eot",
}

/* --- профиль --------------------------------------------------------------- */

// Match -- признаки запроса. Все заданные блоки обязаны совпасть (И); пустой
// Match совпадает со всяким запросом: профиль и так выбран маршрутом.
type Match struct {
	// Префикс пути; путь приезжает без строки запроса.
	PathPrefix string
	// Суффиксы пути, без регистра. Достаточно одного совпавшего.
	Suffixes []string
	// Static добавляет к Suffixes встроенный список расширений статики.
	Static bool
	// Методы; пусто -- любой.
	Methods []string
}

type Rule struct {
	// Имя правила: живёт в логе и аудите, на провод не едет.
	Name  string
	Match Match
	// Phase -- фаза, на которой правило работает: request, response либо
	// пусто (обе). Выдача куки на обеих фазах сразу -- это две выдачи на
	// один запрос, и разводятся они здесь.
	Phase string
	// Status -- коды ответа апстрима, на которых правило работает; только
	// фаза ответа. Пусто -- любой код.
	Status []int
	// On -- состояние куки на входе (absent, present, invalid, expired);
	// пусто -- любое. Cookie -- чьё состояние смотреть.
	On     string
	Cookie string
	// Issue / Drop -- операция правила: выдать либо снять объявленную куку.
	// Имя одно: правило делает одно дело. Пусто у обоих -- правило только
	// рассказывает.
	Issue string
	Drop  string
	// Cond -- имя условия профиля (cond.go); пусто -- правило всегда. Negate
	// -- действия едут, когда условие ложно (`unless:` в файле).
	Cond    string
	Negate  bool
	Actions []Ask
	// Writes -- записи в живые наборы: исполняет сам инспектор, на провод
	// модулю они не едут.
	Writes []Write
}

/*
 * Ask -- просьба канала вместе с именем куки, о которой говорит правило.
 * Имя нужно одному полю -- marker: в нём разворачиваются подстановки {tag},
 * {value} и {name}, а знать их можно только после того, как кука выдана или
 * прочитана. Само действие на провод едет как есть.
 */
type Ask struct {
	Action protocol.Action
	Cookie string
}

/*
 * Write -- запись субъекта запроса в живой набор: адрес клиента, его подсеть
 * или система, либо значение куки (Subject), на срок и с поводом. Это не
 * просьба канала: адресата и оси у неё нет, пишет сам инспектор -- одним
 * кадром keeper.
 */
type Write struct {
	List    string
	Subject string
	Op      string
	// Cookie -- чьё значение писать при Subject == WriteCookie.
	Cookie string
	TTL    time.Duration
	Reason string
}

type Profile struct {
	Name string
	Mode string
	// Conditions -- именованные условия, на которые ссылаются правила.
	Conditions map[string]*Condition
	// Cookies -- объявления: что это за кука, чем заполняется и чем
	// подписывается. Правила ссылаются на них по имени.
	Cookies []*Cookie
	Rules   []Rule
}

// Cookie -- объявление по имени.
func (p *Profile) Cookie(name string) (*Cookie, bool) {
	for _, c := range p.Cookies {
		if c.Name == name {
			return c, true
		}
	}

	return nil, false
}

// NeedsSecret -- хоть одна кука профиля подписывается: без ключа такой профиль
// работать не может, и сказать об этом надо на загрузке, а не на первой куке.
func (p *Profile) NeedsSecret() bool {
	for _, c := range p.Cookies {
		if c.Signed() {
			return true
		}
	}

	return false
}

// Datasets -- имена наборов, которые читают условия профиля: зеркалу их надо
// заказать до первого запроса.
func (p *Profile) Datasets() []string {
	seen := map[string]bool{}

	var out []string

	for _, name := range sortedKeys(p.Conditions) {
		for _, cl := range p.Conditions[name].Clauses {
			if cl.Dataset != "" && !seen[cl.Dataset] {
				seen[cl.Dataset] = true
				out = append(out, cl.Dataset)
			}
		}
	}

	return out
}

func sortedKeys(m map[string]*Condition) []string {
	out := make([]string, 0, len(m))

	for k := range m {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}

// Matches отвечает, накрывает ли правило запрос.
func (m *Match) Matches(method, uri string) bool {
	if m.PathPrefix != "" && !strings.HasPrefix(uri, m.PathPrefix) {
		return false
	}

	if len(m.Methods) > 0 {
		ok := false

		for _, want := range m.Methods {
			if strings.EqualFold(method, want) {
				ok = true
				break
			}
		}

		if !ok {
			return false
		}
	}

	suffixes := m.Suffixes
	if m.Static {
		suffixes = append(append([]string{}, suffixes...), staticSuffixes...)
	}

	if len(suffixes) > 0 {
		lower := strings.ToLower(uri)
		ok := false

		for _, s := range suffixes {
			if strings.HasSuffix(lower, s) {
				ok = true
				break
			}
		}

		if !ok {
			return false
		}
	}

	return true
}

/*
 * Target -- с чем сверяются признаки правила: фаза и запрос, код ответа
 * апстрима (только на фазе ответа) и состояние каждой объявленной куки.
 */
type Target struct {
	Phase  string
	Method string
	URI    string
	Status int
	States map[string]string
}

// Outcome -- что правила решили: какие куки выдать и снять, о чём рассказать
// соседям, что записать в наборы. Rules -- имена сработавших, для аудита.
type Outcome struct {
	Issue   []*Cookie
	Drop    []*Cookie
	Actions []Ask
	Writes  []Write
	Rules   []string
}

/*
 * Collect собирает решение всех совпавших правил. Признак запроса считается
 * раньше условия: у него нет походов в обменник, и правило, снятое по пути,
 * обменник не трогает. ev может быть nil, если у профиля нет условий вовсе.
 *
 * Снятие сильнее выдачи: правило выхода не должно проигрывать правилу
 * посадочной страницы из-за порядка строк. Действия при этом остаются за
 * своими правилами -- сработавшее правило рассказывает соседям то, что в нём
 * написано, независимо от того, чем кончился спор за саму куку.
 */
func (p *Profile) Collect(ev *Evaluator, t *Target) Outcome {
	var out Outcome

	issue := map[string]bool{}
	drop := map[string]bool{}

	for i := range p.Rules {
		r := &p.Rules[i]

		if r.Phase != "" && r.Phase != t.Phase {
			continue
		}

		if !r.Match.Matches(t.Method, t.URI) {
			continue
		}

		if len(r.Status) > 0 && !hasInt(r.Status, t.Status) {
			continue
		}

		if r.On != "" && t.States[r.Cookie] != r.On {
			continue
		}

		if r.Cond != "" {
			holds := ev != nil && ev.Holds(r.Cond)

			if holds == r.Negate {
				continue
			}
		}

		if r.Issue != "" && !issue[r.Issue] {
			if c, ok := p.Cookie(r.Issue); ok {
				issue[r.Issue] = true

				out.Issue = append(out.Issue, c)
			}
		}

		if r.Drop != "" && !drop[r.Drop] {
			if c, ok := p.Cookie(r.Drop); ok {
				drop[r.Drop] = true

				out.Drop = append(out.Drop, c)
			}
		}

		out.Actions = append(out.Actions, r.Actions...)
		out.Writes = append(out.Writes, r.Writes...)
		out.Rules = append(out.Rules, r.Name)
	}

	// Снятое не выдаётся: спор решает снятие, и решается он здесь, а не
	// порядком строк.
	if len(out.Drop) > 0 && len(out.Issue) > 0 {
		kept := out.Issue[:0]

		for _, c := range out.Issue {
			if !drop[c.Name] {
				kept = append(kept, c)
			}
		}

		out.Issue = kept
	}

	return out
}

func hasInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}

	return false
}

/* --- разбор файлов --------------------------------------------------------- */

type fileAction struct {
	To    string `yaml:"to"`
	Do    string `yaml:"do"`
	Apply string `yaml:"apply"`
	// Фаза вызова адресата у управляющих глаголов; пусто -- всем вызовам имени.
	Phase string `yaml:"phase"`
	Code  string `yaml:"code"`
	Delta *int   `yaml:"delta"`
	Value *int   `yaml:"value"`
	// Корзина получателя при do: note -- селектор поверх его правил приёма.
	Counter string `yaml:"counter"`
	// Группа модификаторов получателя и сторона тумблера при do: mutate;
	// у глаголов записи set -- писать или нет.
	Group string `yaml:"group"`
	Set   string `yaml:"set"`
	// Метка события при do: mark, обязательна. Произвольная строка оператора.
	Marker string `yaml:"marker"`
	// Только при do: archive с set on: срок в архиве ("30d"), предел байтами
	// и набор объектов. Без них действует записанное на маршруте.
	TTL string `yaml:"ttl"`
	// Исходы, на которых просьбу исполнять (when= директивы): allow, deny или
	// оба. Пусто -- любой исход, включая перенаправление.
	When    []string             `yaml:"when"`
	Headers *protocol.ObjectSpec `yaml:"headers"`
	Args    *protocol.ObjectSpec `yaml:"args"`
	Body    *protocol.ObjectSpec `yaml:"body"`
	// List -- запись в живой набор вместо просьбы: имя набора, кого писать
	// (Write: addr, net, net_all, asn, cookie) и срок -- тот же ключ ttl.
	// Op -- положить (add, умолчание) либо снять (remove).
	List  string `yaml:"list"`
	Write string `yaml:"write"`
	Op    string `yaml:"op"`
	// Cookie -- чьё значение писать при write: cookie; пусто -- кука
	// правила.
	Cookie string `yaml:"cookie"`
}

type fileMatch struct {
	PathPrefix string   `yaml:"path_prefix"`
	Suffixes   []string `yaml:"suffixes"`
	Static     bool     `yaml:"static"`
	Methods    []string `yaml:"methods"`
}

type fileRule struct {
	Name  string    `yaml:"name"`
	Match fileMatch `yaml:"match"`
	// Фаза правила и коды ответа апстрима; status -- только фаза ответа.
	Phase  string `yaml:"phase"`
	Status []int  `yaml:"status"`
	// Состояние куки на входе и чьё оно. Без issue / drop имя обязательно,
	// если объявлена не одна кука.
	On     string `yaml:"on"`
	Cookie string `yaml:"cookie"`
	// Операция правила: выдать либо снять. Имя объявленной куки.
	Issue string `yaml:"issue"`
	Drop  string `yaml:"drop"`
	// If / Unless -- имя условия профиля: действия едут, когда оно истинно
	// либо, соответственно, ложно. Одно из двух; без обоих -- всегда.
	If      string       `yaml:"if"`
	Unless  string       `yaml:"unless"`
	Actions []fileAction `yaml:"actions"`
}

type fileProfile struct {
	Mode       string          `yaml:"mode"`
	Conditions []fileCondition `yaml:"conditions"`
	Cookies    []fileCookie    `yaml:"cookies"`
	Rules      []fileRule      `yaml:"rules"`
}

func Parse(name string, raw []byte) (*Profile, error) {
	var f fileProfile

	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	p := &Profile{Name: name, Mode: strings.TrimSpace(f.Mode)}

	if p.Mode == "" {
		p.Mode = ModeEnforce
	}

	if p.Mode != ModeEnforce && p.Mode != ModeOff {
		return nil, fmt.Errorf("%s: mode must be enforce or off, got %q", name, p.Mode)
	}

	conds, err := parseConditions(name, f.Conditions)
	if err != nil {
		return nil, err
	}

	p.Conditions = conds

	for i, fc := range f.Cookies {
		at := fmt.Sprintf("%s: cookies[%d]", name, i)

		c, err := parseCookie(at, fc)
		if err != nil {
			return nil, err
		}

		if _, dup := p.Cookie(c.Name); dup {
			return nil, fmt.Errorf("%s: cookie %q is declared twice", at, c.Name)
		}

		p.Cookies = append(p.Cookies, c)
	}

	for i, fr := range f.Rules {
		at := fmt.Sprintf("%s: rules[%d]", name, i)

		rule, err := parseRule(at, i, fr, conds, p)
		if err != nil {
			return nil, err
		}

		p.Rules = append(p.Rules, rule)
	}

	return p, nil
}

func parseRule(at string, index int, fr fileRule, conds map[string]*Condition,
	p *Profile) (Rule, error) {
	rule := Rule{
		Name: strings.TrimSpace(fr.Name),
		Match: Match{
			PathPrefix: strings.TrimSpace(fr.Match.PathPrefix),
			Static:     fr.Match.Static,
		},
	}

	// Имя живёт только в логе и аудите; не назвали -- порядковое. Требовать
	// его значило бы заставлять придумывать слова тому, у кого их нет.
	if rule.Name == "" {
		rule.Name = fmt.Sprintf("rule-%d", index+1)
	}

	/*
	 * Ссылка на условие -- только на объявленное: опечатка в имени иначе
	 * становилась бы правилом, которое не срабатывает никогда (if) либо
	 * срабатывает всегда (unless), и ни то ни другое не видно.
	 */
	ifName, unlessName := strings.TrimSpace(fr.If), strings.TrimSpace(fr.Unless)

	if ifName != "" && unlessName != "" {
		return rule, fmt.Errorf("%s: if and unless together -- pick one", at)
	}

	rule.Cond = ifName
	rule.Negate = unlessName != ""

	if rule.Negate {
		rule.Cond = unlessName
	}

	if rule.Cond != "" {
		if _, ok := conds[rule.Cond]; !ok {
			return rule, fmt.Errorf("%s: condition %q is not declared in conditions", at, rule.Cond)
		}
	}

	for _, s := range fr.Match.Suffixes {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			return rule, fmt.Errorf("%s: empty suffix", at)
		}

		rule.Match.Suffixes = append(rule.Match.Suffixes, s)
	}

	for _, m := range fr.Match.Methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" {
			return rule, fmt.Errorf("%s: empty method", at)
		}

		rule.Match.Methods = append(rule.Match.Methods, m)
	}

	if err := parseRuleCookie(at, fr, &rule, p); err != nil {
		return rule, err
	}

	/*
	 * Правило без операции и без действий не делает ничего. У инспектора
	 * действий это была верная проверка целиком; здесь она мягче -- правило
	 * вправе только выдать куку и ничего не рассказывать.
	 */
	if len(fr.Actions) == 0 && rule.Issue == "" && rule.Drop == "" {
		return rule, fmt.Errorf("%s: the rule neither issues, drops nor sends anything", at)
	}

	for j, fa := range fr.Actions {
		where := fmt.Sprintf("%s.actions[%d]", at, j)

		// Строка с набором -- запись, а не просьба: исполняет сам инспектор.
		if strings.TrimSpace(fa.List) != "" {
			w, err := parseWrite(where, fa, &rule, p)
			if err != nil {
				return rule, err
			}

			rule.Writes = append(rule.Writes, w)

			continue
		}

		action, err := parseAction(where, fa)
		if err != nil {
			return rule, err
		}

		rule.Actions = append(rule.Actions, Ask{Action: action, Cookie: rule.Cookie})
	}

	return rule, nil
}

/*
 * parseRuleCookie -- фаза, код ответа, состояние и операция. Здесь же
 * выясняется, о какой куке правило говорит: её называет issue / drop, а если
 * операции нет -- поле cookie; при единственной объявленной куке имя можно не
 * писать вовсе.
 */
func parseRuleCookie(at string, fr fileRule, rule *Rule, p *Profile) error {
	rule.Phase = strings.TrimSpace(fr.Phase)

	switch rule.Phase {
	case "", protocol.PhaseRequest, protocol.PhaseResponse:
	default:
		return fmt.Errorf("%s: phase must be request or response, got %q", at, rule.Phase)
	}

	for _, code := range fr.Status {
		if code < 100 || code > 599 {
			return fmt.Errorf("%s: status %d is not an http status", at, code)
		}

		rule.Status = append(rule.Status, code)
	}

	/*
	 * Код ответа знает только фаза ответа. На фазе запроса его нет вовсе, и
	 * правило с ним не срабатывало бы никогда -- молча.
	 */
	if len(rule.Status) > 0 && rule.Phase != protocol.PhaseResponse {
		return fmt.Errorf("%s: status needs phase: %s", at, protocol.PhaseResponse)
	}

	rule.Issue = strings.TrimSpace(fr.Issue)
	rule.Drop = strings.TrimSpace(fr.Drop)

	if rule.Issue != "" && rule.Drop != "" {
		return fmt.Errorf("%s: issue and drop together -- a rule does one thing", at)
	}

	for _, name := range []string{rule.Issue, rule.Drop} {
		if name == "" {
			continue
		}

		if _, ok := p.Cookie(name); !ok {
			return fmt.Errorf("%s: cookie %q is not declared in cookies", at, name)
		}
	}

	rule.Cookie = strings.TrimSpace(fr.Cookie)
	rule.On = strings.TrimSpace(fr.On)

	if rule.Cookie == "" {
		switch {
		case rule.Issue != "":
			rule.Cookie = rule.Issue
		case rule.Drop != "":
			rule.Cookie = rule.Drop
		case len(p.Cookies) == 1:
			rule.Cookie = p.Cookies[0].Name
		}
	}

	if rule.Cookie != "" {
		if _, ok := p.Cookie(rule.Cookie); !ok {
			return fmt.Errorf("%s: cookie %q is not declared in cookies", at, rule.Cookie)
		}
	}

	if rule.On == "" {
		return nil
	}

	if rule.Cookie == "" {
		return fmt.Errorf("%s: on %q needs cookie: which one", at, rule.On)
	}

	known := false

	for _, s := range States {
		if s == rule.On {
			known = true
			break
		}
	}

	if !known {
		return fmt.Errorf("%s: on must be one of %s, got %q",
			at, strings.Join(States, ", "), rule.On)
	}

	c, _ := p.Cookie(rule.Cookie)

	/*
	 * Состояния, которых у неподписанной куки не бывает: предъявленное
	 * значение не с чем сверить, а времени выдачи в нём нет. Правило,
	 * которое не срабатывает никогда, -- это опечатка, и находиться она
	 * должна на загрузке.
	 */
	if !c.Signed() && (rule.On == StateInvalid || rule.On == StateExpired) {
		return fmt.Errorf("%s: on %s needs sign: %s on cookie %q",
			at, rule.On, SignHMAC, c.Name)
	}

	if rule.On == StateExpired && c.Renew == 0 {
		return fmt.Errorf("%s: on %s needs renew_after on cookie %q",
			at, StateExpired, c.Name)
	}

	return nil
}

/*
 * parseWrite -- запись в живой набор. Кого писать: адрес клиента (addr, по
 * умолчанию) либо то, во что он разворачивается у кодера гео. Срок
 * обязателен: запись без срока пережила бы причину, по которой её сделали.
 * Остальные поля просьбы здесь -- битая форма: у записи нет ни адресата, ни
 * оси, ни глагола, и молча отброшенное поле выглядело бы работающим.
 */
func parseWrite(at string, fa fileAction, rule *Rule, p *Profile) (Write, error) {
	w := Write{
		List:    strings.TrimSpace(fa.List),
		Subject: strings.TrimSpace(fa.Write),
		Op:      strings.TrimSpace(fa.Op),
		Cookie:  strings.TrimSpace(fa.Cookie),
		Reason:  strings.TrimSpace(fa.Code),
	}

	if w.Subject == "" {
		w.Subject = WriteAddr
	}

	if w.Op == "" {
		w.Op = OpAdd
	}

	if !counterRe.MatchString(w.List) {
		return w, fmt.Errorf("%s: list %q is not a dataset name", at, w.List)
	}

	switch w.Subject {
	case WriteAddr, WriteNet, WriteNetAll, WriteASN:
	case WriteCookie:
		if w.Cookie == "" {
			w.Cookie = rule.Cookie
		}

		if w.Cookie == "" {
			return w, fmt.Errorf("%s: write %s needs cookie: whose value to write",
				at, WriteCookie)
		}

		if _, ok := p.Cookie(w.Cookie); !ok {
			return w, fmt.Errorf("%s: cookie %q is not declared in cookies", at, w.Cookie)
		}
	default:
		return w, fmt.Errorf("%s: write must be %s, %s, %s, %s or %s, got %q",
			at, WriteAddr, WriteNet, WriteNetAll, WriteASN, WriteCookie, w.Subject)
	}

	if w.Cookie != "" && w.Subject != WriteCookie {
		return w, fmt.Errorf("%s: cookie is only for write: %s", at, WriteCookie)
	}

	if strings.TrimSpace(fa.Do) != "" || strings.TrimSpace(fa.To) != "" ||
		strings.TrimSpace(fa.Apply) != "" || strings.TrimSpace(fa.Phase) != "" ||
		fa.Delta != nil || fa.Value != nil || strings.TrimSpace(fa.Counter) != "" ||
		strings.TrimSpace(fa.Group) != "" || strings.TrimSpace(fa.Set) != "" ||
		strings.TrimSpace(fa.Marker) != "" || len(fa.When) != 0 ||
		fa.Headers != nil || fa.Args != nil || fa.Body != nil {
		return w, fmt.Errorf("%s: a list write takes only list, write, op, cookie, ttl and code", at)
	}

	/*
	 * Снятие срока не имеет: запись либо есть, либо её больше нет. Срок у
	 * remove читался бы как «снять на час», а это не то, что произойдёт.
	 */
	if w.Op == OpRemove {
		if strings.TrimSpace(fa.TTL) != "" {
			return w, fmt.Errorf("%s: op %s takes no ttl", at, OpRemove)
		}

		if w.Reason == "" {
			w.Reason = DefaultWriteReason
		} else if !codeRe.MatchString(w.Reason) {
			return w, fmt.Errorf("%s: code %q is not [A-Z][A-Z0-9_]{0,63}", at, w.Reason)
		}

		return w, nil
	}

	if w.Op != OpAdd {
		return w, fmt.Errorf("%s: op must be %s or %s, got %q", at, OpAdd, OpRemove, w.Op)
	}

	if strings.TrimSpace(fa.TTL) == "" {
		return w, fmt.Errorf("%s: a list write needs ttl", at)
	}

	ttl, err := parseTTL(fa.TTL)
	if err != nil {
		return w, fmt.Errorf("%s: %w", at, err)
	}

	if ttl < time.Second {
		return w, fmt.Errorf("%s: ttl %q is shorter than a second", at, fa.TTL)
	}

	w.TTL = ttl

	if w.Reason == "" {
		w.Reason = DefaultWriteReason
	} else if !codeRe.MatchString(w.Reason) {
		return w, fmt.Errorf("%s: code %q is not [A-Z][A-Z0-9_]{0,63}", at, w.Reason)
	}

	return w, nil
}

// controlVerb -- глагол исполняет модуль в адрес вызова соседа.
func controlVerb(do string) bool {
	switch do {
	case protocol.DoActive, protocol.DoPassive, protocol.DoVote, protocol.DoOff:
		return true
	}

	return false
}

// checkPhaseAsk -- фаза вызова адресата: только у управляющих глаголов, одно
// из request, response, frame; с осью conn -- только frame либо без поля: до
// конца соединения живут одни кадры. Пусто -- всем вызовам имени.
func checkPhaseAsk(do, phase, apply string) error {
	if phase == "" {
		return nil
	}

	if !controlVerb(do) {
		return fmt.Errorf("phase is only for active, passive, vote and off")
	}

	switch phase {
	case protocol.PhaseRequest, protocol.PhaseResponse, protocol.PhaseFrame:
	default:
		return fmt.Errorf("phase must be request, response or frame, got %q", phase)
	}

	if apply == protocol.ApplyConn && phase != protocol.PhaseFrame {
		return fmt.Errorf("apply conn needs phase frame")
	}

	return nil
}

func parseAction(at string, fa fileAction) (protocol.Action, error) {
	action := protocol.Action{
		To:      strings.TrimSpace(fa.To),
		Do:      strings.TrimSpace(fa.Do),
		Apply:   strings.TrimSpace(fa.Apply),
		Phase:   strings.TrimSpace(fa.Phase),
		Code:    strings.TrimSpace(fa.Code),
		Delta:   fa.Delta,
		Value:   fa.Value,
		Counter: strings.TrimSpace(fa.Counter),
		Marker:  strings.TrimSpace(fa.Marker),
		Group:   strings.TrimSpace(fa.Group),
		Set:     strings.TrimSpace(fa.Set),
		Headers: fa.Headers,
		Args:    fa.Args,
		Body:    fa.Body,
	}

	// Кого писать -- слово записи в набор; у просьбы ему нечего значить.
	if strings.TrimSpace(fa.Write) != "" {
		return action, fmt.Errorf("%s: write is only for a list write", at)
	}

	if strings.TrimSpace(fa.TTL) != "" {
		d, err := parseTTL(fa.TTL)
		if err != nil {
			return action, fmt.Errorf("%s: %w", at, err)
		}

		ttl := int64(d / time.Second)
		action.TTL = &ttl
	}

	when, err := protocol.CheckArchiveWhen(fa.When)
	if err != nil {
		return action, fmt.Errorf("%s: %w", at, err)
	}

	action.When = when

	/*
	 * Адресат обязателен. Просьба без него доезжает до всех, и применить её
	 * вправе кто угодно: шина рекомендательная, но круг слушателей -- решение
	 * отправителя, и у правила, которое пишут руками, он должен быть написан.
	 * Исключение -- глаголы записи: их адресат -- запись маршрута, и поля to
	 * у них нет по построению.
	 */
	if action.To == "" && !recordVerb(action.Do) {
		return action, fmt.Errorf("%s: to is empty", at)
	}

	axes, ok := verbs[action.Do]
	if !ok {
		return action, fmt.Errorf("%s: unknown do %q", at, action.Do)
	}

	// Ось: где выбора нет, её проставляет словарь. Пустой она уехать не может --
	// действие без оси модуль отбраковывает вместе со всем ответом.
	// У глаголов записи умолчание -- запись запроса (первая ось словаря):
	// правила, писанные до оси response, читаются как прежде.
	if action.Apply == "" && (len(axes) == 1 || recordVerb(action.Do)) {
		action.Apply = axes[0]
	}

	axisOK := false

	for _, a := range axes {
		if a == action.Apply {
			axisOK = true
			break
		}
	}

	if !axisOK {
		return action, fmt.Errorf("%s: apply %q is not allowed for %q (want %s)",
			at, action.Apply, action.Do, strings.Join(axes, ", "))
	}

	if err := checkPhaseAsk(action.Do, action.Phase, action.Apply); err != nil {
		return action, fmt.Errorf("%s: %w", at, err)
	}

	if action.Code != "" && !codeRe.MatchString(action.Code) {
		return action, fmt.Errorf("%s: code %q is not [A-Z][A-Z0-9_]{0,63}", at, action.Code)
	}

	switch action.Do {
	case protocol.DoThreshold:
		if action.Delta == nil {
			return action, fmt.Errorf("%s: threshold requires delta", at)
		}

		// Проценты коэффициента к измерению получателя: множитель
		// 1 + delta/100. Минус -- скидка, плюс -- строже.
		if *action.Delta < -100 || *action.Delta > 900 {
			return action, fmt.Errorf("%s: delta %d is out of -100..900 percent", at, *action.Delta)
		}
	default:
		if action.Delta != nil {
			return action, fmt.Errorf("%s: delta is only for threshold", at)
		}
	}

	switch action.Do {
	case protocol.DoScore:
		// Очки: value обязателен и со знаком, вклад одного инспектора не
		// сильнее сотни; адресат -- сумма самого маршрута.
		if action.Value == nil || *action.Value == 0 {
			return action, fmt.Errorf("%s: score needs a non-zero value", at)
		}

		if *action.Value < -100 || *action.Value > 100 {
			return action, fmt.Errorf("%s: value %d is out of -100..100", at, *action.Value)
		}

		if action.To != "" && action.To != "*" {
			return action, fmt.Errorf("%s: score takes no to: the module adds to the route's own sum", at)
		}

		if action.Counter != "" {
			return action, fmt.Errorf("%s: counter is only for note", at)
		}
	case protocol.DoNote:
		// Проценты шкалы счётчика получателя: плюс пополняет долей порога,
		// минус снимает долю накопленного. Знак применит только получатель,
		// у которого есть правило на этого отправителя по имени.
		if action.Value != nil && (*action.Value < -100 || *action.Value > 100) {
			return action, fmt.Errorf("%s: value %d is out of -100..100 percent", at, *action.Value)
		}

		// Корзина -- селектор поверх правил приёма получателя: имя проходит
		// только через правило, которое его и выдаёт. Пусто -- корзину
		// называет правило.
		if action.Counter != "" && !counterRe.MatchString(action.Counter) {
			return action, fmt.Errorf("%s: counter %q is not a name", at, action.Counter)
		}
	default:
		if action.Value != nil {
			return action, fmt.Errorf("%s: value is only for note and score", at)
		}

		if action.Counter != "" {
			return action, fmt.Errorf("%s: counter is only for note", at)
		}
	}

	// Группа и сторона -- только у mutate, и у mutate -- обе: что именно
	// переключить и куда, называет отправитель, как корзину у note.
	if action.Do == protocol.DoMutate {
		if action.Group == "" {
			return action, fmt.Errorf("%s: mutate needs a group", at)
		}

		if !counterRe.MatchString(action.Group) {
			return action, fmt.Errorf("%s: group %q is not a name", at, action.Group)
		}

		if action.Set != "on" && action.Set != "off" {
			return action, fmt.Errorf("%s: mutate needs set: on or off, got %q", at, action.Set)
		}
	} else if action.Group != "" || (action.Set != "" && !auditVerb(action.Do)) {
		return action, fmt.Errorf("%s: group and set are only for mutate", at)
	}

	/*
	 * Метка -- только у mark, и у mark она обязательна: "пометить" без метки
	 * не просьба. Адресат -- запись маршрута, поэтому названный сосед здесь
	 * та же битая форма, что у глаголов записи.
	 */
	if action.Do == protocol.DoMark {
		if action.To != "" && action.To != "*" {
			return action, fmt.Errorf("%s: %s takes no to: the module marks the route's own record", at, action.Do)
		}

		if err := protocol.CheckMarker(action.Marker); err != nil {
			return action, fmt.Errorf("%s: %w", at, err)
		}
	} else if action.Marker != "" {
		return action, fmt.Errorf("%s: marker is only for %q", at, protocol.DoMark)
	}

	ttl := int64(0)
	if action.TTL != nil {
		ttl = *action.TTL
	}

	// Глагол записи: адресат -- запись маршрута, поля to нет; сторона
	// обязательна; срок, предел и набор объектов -- только у archive с set on.
	if auditVerb(action.Do) {
		if action.To != "" && action.To != "*" {
			return action, fmt.Errorf("%s: %s takes no to: the module writes the route's own record", at, action.Do)
		}

		if action.Set != "on" && action.Set != "off" {
			return action, fmt.Errorf("%s: %s needs set: on or off, got %q", at, action.Do, action.Set)
		}

		if action.Set == "off" && (ttl != 0 || len(action.When) != 0 || action.Headers != nil || action.Args != nil || action.Body != nil) {
			return action, fmt.Errorf("%s: ttl, when and objects are only for set on", at)
		}

		if action.Do == protocol.DoAudit && (ttl != 0 || len(action.When) != 0) {
			return action, fmt.Errorf("%s: ttl and when are only for archive", at)
		}

		// У записи ответа строки запроса нет.
		if action.Apply == protocol.ApplyResponse && action.Args != nil {
			return action, fmt.Errorf("%s: args has no meaning for the response record", at)
		}

		for _, item := range []struct {
			name string
			spec *protocol.ObjectSpec
		}{{"headers", action.Headers}, {"args", action.Args}, {"body", action.Body}} {
			if err := protocol.CheckObjectSpec(item.name, item.spec, action.Do == protocol.DoAudit); err != nil {
				return action, fmt.Errorf("%s: %w", at, err)
			}
		}
	}

	if !auditVerb(action.Do) && (action.TTL != nil || len(action.When) != 0 ||
		action.Headers != nil || action.Args != nil || action.Body != nil) {
		return action, fmt.Errorf("%s: ttl, when, headers, args and body are only for audit and archive", at)
	}

	return action, nil
}

// parseTTL -- срок архива: как time.ParseDuration, плюс сутки ("30d"): срок в
// архиве считают днями, а не часами, и остальные загрузчики его так и читают.
func parseTTL(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)

	if strings.HasSuffix(raw, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(raw, "d"))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("bad ttl %q", raw)
		}

		return time.Duration(n) * 24 * time.Hour, nil
	}

	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("bad ttl %q", raw)
	}

	return d, nil
}

/* --- каталог --------------------------------------------------------------- */

// LoadDir читает каталог профилей: один файл <имя>.yaml на профиль.
func LoadDir(dir string) (map[string]*Profile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	out := make(map[string]*Profile)

	for _, e := range entries {
		name, ok := profileName(e)
		if !ok {
			continue
		}

		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}

		p, err := Parse(name, raw)
		if err != nil {
			return nil, err
		}

		out[name] = p
	}

	return out, nil
}

func profileName(e os.DirEntry) (string, bool) {
	if e.IsDir() || strings.HasPrefix(e.Name(), ".") || strings.HasPrefix(e.Name(), "_") {
		return "", false
	}

	name, found := strings.CutSuffix(e.Name(), ".yaml")
	if !found {
		name, found = strings.CutSuffix(e.Name(), ".yml")
	}

	if !found || name == "" {
		return "", false
	}

	return strings.ToLower(name), true
}

func Names(profiles map[string]*Profile) []string {
	out := make([]string, 0, len(profiles))

	for name := range profiles {
		out = append(out, name)
	}

	sort.Strings(out)

	return out
}
