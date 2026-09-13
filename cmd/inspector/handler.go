/*
 * Конвейер одного сообщения: разбор -> очередь -> состояние кук -> правила ->
 * ответ с секцией cookies и действиями.
 *
 * Вердикта, кроме allow, у инспектора нет: он ничего не проверяет. Он ставит
 * куку, снимает её, пишет её значение в живые наборы и рассказывает соседям.
 * Решает по ней уже не он -- локальный слой на краю, автодействия, счётчик.
 *
 * Свои сбои -- битое сообщение, чужая версия, неизвестный профиль, перегрузка,
 * паника, недоступный обменник, отсутствующий ключ подписи -- это verdict
 * error. Allow на них прятал бы поломку: кука не выдана, а ответ выглядит
 * годным, и предохранитель считает сыплющийся процесс здоровым.
 *
 * Работает на обеих фазах. На фазе запроса кука ставится до апстрима -- её
 * увидит и приложение в своём же ответе; на фазе ответа -- после, и там видно
 * код ответа (status:), то есть можно не выдавать куку тому, кому апстрим
 * ответил 404. Заголовки запроса на поздней фазе берутся из request_store:
 * Cookie предъявляет клиент, а не апстрим.
 */

package main

import (
	"context"
	"errors"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-cookie/internal/audit"
	"github.com/exemt/placitum-cookie/internal/body"
	"github.com/exemt/placitum-cookie/internal/config"
	"github.com/exemt/placitum-cookie/internal/livelist"
	"github.com/exemt/placitum-cookie/internal/policy"
	"github.com/exemt/placitum-cookie/internal/protocol"
	"github.com/exemt/placitum-cookie/internal/queue"
	"github.com/exemt/placitum-shared/dataset"
	"github.com/exemt/placitum-shared/netinfo"
)

const (
	codeOK                 = "COOKIE_OK"
	codeMalformedRequest   = "COOKIE_MALFORMED_REQUEST"
	codeUnsupportedVersion = "COOKIE_UNSUPPORTED_VERSION"
	codeUnknownProfile     = "COOKIE_UNKNOWN_PROFILE"
	codeProfileOff         = "COOKIE_PROFILE_OFF"
	codeIdle               = "COOKIE_IDLE"
	codeInternalError      = "COOKIE_INTERNAL_ERROR"
	// Обменник подвёл на объекте, который лежал: состояние куки и условия
	// профиля посчитаны без данных. Сбой инспектора, а не свойство запроса.
	codeStoreError = "COOKIE_STORE_ERROR"
	/*
	 * Маршрут не снимает заголовки запроса, а профиль объявляет куки: Cookie
	 * читать не по чему. Отвечать allow здесь нельзя -- это означало бы
	 * «куки нет» на каждом запросе, то есть выдачу новой куки всем и всегда.
	 */
	codeHeadersUnavailable = "COOKIE_HEADERS_UNAVAILABLE"
	// Кука подписывается, а ключа у процесса нет (WAF_COOKIE_SECRET).
	codeSecretMissing = "COOKIE_SECRET_MISSING"
	// Значение не собралось: длиннее предела, источник случайного не дал байт.
	codeIssueFailed = "COOKIE_ISSUE_FAILED"
	// Правило пишет в набор подсеть или систему (write: net | net_all | asn),
	// а кодер гео молчит: записи не будет, и молча пропускать её нельзя.
	codeGeoUnavailable = "COOKIE_GEO_UNAVAILABLE"
)

type handler struct {
	cfg   *config.Config
	log   *slog.Logger
	nc    *nats.Conn
	audit *audit.Sink
	store *policy.Store
	pool  *queue.Pool
	// loader -- обменник объектов: заголовки запроса (в них Cookie) и строка
	// запроса; mirror -- зеркало активных наборов для условий по спискам.
	loader *body.Loader
	mirror *livelist.Mirror
	// lists -- записи правил в живые наборы; resolver -- кодер гео: анонсы
	// и состав системы, когда правило пишет не адрес (net, net_all, asn).
	// nil-кодер -- такие строки отвечают error, адрес пишется как всегда.
	lists    *dataset.Publisher
	resolver *netinfo.Resolver
	// secret -- ключ подписи значений. Пусто -- профили с sign: hmac
	// отвечают error: тихо выдать неподписанную куку вместо подписанной
	// значит открыть ровно ту дыру, ради закрытия которой подпись и завели.
	secret []byte
}

// receive исполняется в потоке приёма и обязан быть дешёвым: разбор нужен,
// потому что без deadline_ms не проверить бюджет, остальное уходит в пул.
func (h *handler) receive(msg *nats.Msg) {
	defer h.recoverInto(msg.Reply, "")

	req, err := protocol.Parse(msg.Data)
	if err != nil {
		h.log.Warn("message rejected", "error", err.Error(), "bytes", len(msg.Data))
		h.send(msg.Reply, h.fallback(msg.Data, codeMalformedRequest), nil, audit.Details{})

		return
	}

	if !h.cfg.Supports(req.V) {
		h.send(msg.Reply, h.plain(req, codeUnsupportedVersion), req, audit.Details{})

		return
	}

	// Состояния между фазами инспектор не держит, освобождать нечего. Ответа
	// на release не бывает -- слот в модуле уже закрыт.
	if req.Release != nil {
		h.log.Debug("release ignored", "rid", req.RID, "reason", req.Release.Reason)

		return
	}

	/*
	 * Кадры WebSocket: своей куки у кадра нет -- заголовки остались на
	 * рукопожатии, а Set-Cookie в кадр не положить. Allow без действий, и
	 * сразу, мимо очереди.
	 */
	if req.Phase != protocol.PhaseRequest && req.Phase != protocol.PhaseResponse {
		h.send(msg.Reply, h.plain(req, codeIdle), req, audit.Details{})

		return
	}

	h.pool.Submit(&queue.Task{Req: req, Reply: msg.Reply})
}

/*
 * evaluate исполняется воркером. shed непустой означает, что до правил дело не
 * дошло: очередь была полна либо бюджет вышел. Ответ -- error класса overload,
 * как у остальных инспекторов: кука, которую не выдали, ничем не отличается от
 * выданной, если смотреть на allow.
 */
func (h *handler) evaluate(t *queue.Task, budget time.Duration, shed string) {
	defer h.recoverInto(t.Reply, t.Req.RID)

	if shed != "" {
		reply := protocol.ShedReply(t.Req, shed)
		det := audit.Details{Engine: map[string]any{"shed": shed}}

		asks := h.overloadOnShed(t, shed, reply, det)

		h.log.Warn("shed", "rid", t.Req.RID, "reason", shed,
			"budget_ms", budget.Milliseconds(), "asks", asks)
		h.send(t.Reply, reply, t.Req, det)

		return
	}

	reply, det := h.inspect(t.Req, t.Fill, budget)
	h.send(t.Reply, reply, t.Req, det)
}

func (h *handler) inspect(req *protocol.Request, fill int, budget time.Duration) (*protocol.Reply, audit.Details) {
	snap := h.store.Current()

	/*
	 * Профиля с таким именем нет. Отката на default не бывает: чужой профиль
	 * -- это чужая кука с чужим сроком и чужой меткой, а не более тихая
	 * версия своей.
	 */
	p, ok := snap.Profile(req.Route.Profile)
	if !ok {
		h.log.Warn("unknown profile", "rid", req.RID, "profile", req.Route.Profile)

		return protocol.ErrorReply(req, codeUnknownProfile), audit.Details{}
	}

	if p.Mode == policy.ModeOff {
		return h.plain(req, codeProfileOff), audit.Details{}
	}

	started := time.Now()
	engine := map[string]any{"profile": p.Name, "mode": p.Mode}

	det := func() audit.Details {
		return audit.Details{
			EngineMS: float64(time.Since(started).Microseconds()) / 1000,
			Engine:   engine,
		}
	}

	// Бюджет сообщения -- на всё, что ходит наружу: обменник за заголовками и
	// кодер гео для записей в наборы.
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	src := newSource(ctx, req, h.loader)

	/*
	 * Заголовков запроса нет -- читать Cookie не по чему. Профиль без
	 * объявлений это переживает (он тогда только рассказывает), профиль с
	 * куками -- нет: «куки нет» на каждом запросе превратилось бы в новую
	 * куку каждому, и каждый раз новую.
	 */
	if len(p.Cookies) > 0 && !src.HeadersPlaced() {
		h.log.Warn("request headers are not captured on the route",
			"rid", req.RID, "profile", p.Name)

		engine["store"] = "request headers are not in waf_capture"

		return protocol.ErrorReply(req, codeHeadersUnavailable), det()
	}

	now := time.Now()

	states, values, err := h.states(p, src, now)
	if err != nil {
		return h.stateError(req, p, src, engine, err), det()
	}

	var ev *policy.Evaluator

	if len(p.Conditions) > 0 {
		ev = policy.NewEvaluator(src, h.mirror, p.Conditions)
	}

	target := &policy.Target{
		Phase:  req.Phase,
		Method: req.HTTP.Method,
		URI:    req.HTTP.URI,
		States: states,
	}

	if req.Response != nil {
		target.Status = req.Response.Status
	}

	out := p.Collect(ev, target)

	// Строки перегрузки -- только на фазе запроса: запрос встал в очередь не
	// ниже их порога.
	if req.Phase == protocol.PhaseRequest {
		more := p.CollectOverload(fill, false)
		out.Actions = append(out.Actions, more.Actions...)
		out.Writes = append(out.Writes, more.Writes...)
		out.Rules = append(out.Rules, more.Rules...)
	}

	engine["rules"] = out.Rules

	if ev != nil {
		if len(ev.Evaluated()) > 0 {
			engine["conditions"] = ev.Evaluated()
		}

		if len(ev.Notes) > 0 {
			engine["notes"] = ev.Notes
		}
	}

	/*
	 * Объект лежал в обменнике, а взять его не вышло: и состояние куки, и
	 * условия посчитаны без данных, которые были рядом. Проверяется после
	 * правил -- условие могло и не понадобиться.
	 */
	if src.Fault {
		h.log.Warn("store failed", "rid", req.RID, "profile", p.Name, "detail", src.Why)

		engine["store"] = src.Why

		return protocol.ErrorReply(req, codeStoreError), det()
	}

	cookies, err := h.apply(&out, values, now, src)
	if err != nil {
		h.log.Error("cookie not issued", "rid", req.RID, "profile", p.Name,
			"error", err.Error())

		engine["cookie"] = err.Error()

		code := codeIssueFailed
		if errors.Is(err, policy.ErrNoSecret) {
			code = codeSecretMissing
		}

		return protocol.ErrorReply(req, code), det()
	}

	if len(cookies) > 0 {
		engine["cookies"] = cookieNames(cookies)
	}

	if len(out.Writes) != 0 {
		engine["lists"] = len(out.Writes)
	}

	/*
	 * Правило требует кодер, а кодер молчит: запись в набор не состоялась.
	 * Молча пропустить нельзя -- записи, которой не было, не видно ничем,
	 * -- поэтому error; что делать с запросом, решает waf_exception маршрута.
	 */
	if err := h.publish(ctx, out.Writes, values, req); err != nil {
		h.log.Error("geo unavailable for a list write", "rid", req.RID,
			"profile", p.Name, "error", err.Error())

		engine["geo"] = err.Error()

		return protocol.ErrorReply(req, codeGeoUnavailable), det()
	}

	reply := h.plain(req, codeOK)
	reply.Cookies = cookies
	actions, dropped := expand(out.Actions, values)
	reply.Actions = actions

	/*
	 * Метка развернулась в пустую строку: подстановка есть, значения нет.
	 * Пустую метку модуль отбраковывает вместе со всем ответом, поэтому
	 * действие снимается здесь -- громко, строкой в журнале.
	 */
	if len(dropped) > 0 {
		h.log.Warn("marker expands to nothing", "rid", req.RID, "profile", p.Name,
			"cookies", dropped)

		engine["markers_dropped"] = dropped
	}

	h.log.Info("told",
		"rid", req.RID,
		"inspector", req.Inspector,
		"phase", req.Phase,
		"wave", req.Wave,
		"method", req.HTTP.Method,
		"uri", req.HTTP.URI,
		"profile", p.Name,
		"rules", out.Rules,
		"cookies", cookieNames(cookies),
		"actions", len(reply.Actions),
		"lists", len(out.Writes),
	)

	return reply, det()
}

/*
 * seen -- то, что известно про куку на этом запросе: значение, которое
 * предъявил клиент либо которое мы только что выдали, и его метка. Ключ карты
 * -- имя куки; по ней разворачиваются подстановки маркера и берётся значение
 * для записи в набор.
 */
type seen struct {
	Value string
	Tag   string
}

// states читает предъявленные куки и считает их состояния. Ошибка здесь одна
// -- нет ключа подписи: состояние подписанной куки без ключа не определить.
func (h *handler) states(p *policy.Profile, src *source, now time.Time) (
	map[string]string, map[string]seen, error) {

	states := make(map[string]string, len(p.Cookies))
	values := make(map[string]seen, len(p.Cookies))

	if len(p.Cookies) == 0 {
		return states, values, nil
	}

	pairs, ok := src.Cookies()

	for _, c := range p.Cookies {
		raw := ""

		if ok {
			for _, pair := range pairs {
				if pair.Name == c.Name {
					raw = pair.Value
					break
				}
			}
		}

		state, tag, err := c.Read(raw, now, h.secret)
		if err != nil {
			return nil, nil, err
		}

		states[c.Name] = state

		if state == policy.StatePresent || state == policy.StateExpired {
			values[c.Name] = seen{Value: raw, Tag: tag}
		}
	}

	return states, values, nil
}

// stateError -- ошибка чтения состояний: либо обменник (Fault уже помечен),
// либо ключ подписи.
func (h *handler) stateError(req *protocol.Request, p *policy.Profile, src *source,
	engine map[string]any, err error) *protocol.Reply {

	if src.Fault {
		h.log.Warn("store failed", "rid", req.RID, "profile", p.Name, "detail", src.Why)
		engine["store"] = src.Why

		return protocol.ErrorReply(req, codeStoreError)
	}

	h.log.Error("cookie state unknown", "rid", req.RID, "profile", p.Name,
		"error", err.Error())

	engine["cookie"] = err.Error()

	if errors.Is(err, policy.ErrNoSecret) {
		return protocol.ErrorReply(req, codeSecretMissing)
	}

	return protocol.ErrorReply(req, codeIssueFailed)
}

/*
 * apply исполняет решение правил: собирает секцию cookies и правит карту
 * значений, чтобы маркеры и записи в наборы говорили о том, что клиент унесёт
 * с этим ответом, а не о том, что он принёс.
 *
 * Снятая кука из карты НЕ исчезает, и это существенно: строка op: remove
 * снимает из набора ровно то значение, которое мы только что отозвали, и без
 * него снятие остаётся без субъекта. Выданная -- заменяет прочитанную: в набор
 * и в маркер идёт то, что клиент унесёт.
 */
func (h *handler) apply(out *policy.Outcome, values map[string]seen, now time.Time,
	src policy.Source) ([]protocol.Cookie, error) {

	var cookies []protocol.Cookie

	for _, c := range out.Issue {
		value, tag, err := c.Issue(src, now, h.secret)
		if err != nil {
			return nil, err
		}

		item := protocol.Cookie{Name: c.Name, Value: value, Path: c.Path}

		if c.MaxAgeSet {
			age := int(c.MaxAge / time.Second)
			item.MaxAge = &age
		}

		cookies = append(cookies, item)
		values[c.Name] = seen{Value: value, Tag: tag}
	}

	for _, c := range out.Drop {
		/*
		 * Снятие -- пустое значение и Max-Age=0 на том же пути. Путь
		 * обязателен и обязан совпасть с выданным: браузер различает куки
		 * по тройке (домен, путь, имя), и снятие с другого пути оставляет
		 * старую на месте, а клиенту добавляет вторую.
		 */
		zero := 0
		cookies = append(cookies, protocol.Cookie{
			Name: c.Name, Value: "", Path: c.Path, MaxAge: &zero,
		})
	}

	return cookies, nil
}

/*
 * publish -- записи правил в живые наборы, см. lists.go: адрес клиента как
 * есть, анонсы и состав системы -- у кодера, значение куки -- из карты. Отказ
 * keeper не отменяет ничего; ошибка -- кодер нужен и молчит.
 */
func (h *handler) publish(ctx context.Context, writes []policy.Write, values map[string]seen,
	req *protocol.Request) error {

	if len(writes) == 0 || h.lists == nil {
		return nil
	}

	cookies := make(map[string]string, len(values))

	for name, v := range values {
		cookies[name] = v.Value
	}

	return writeLists(ctx, h.resolver, h.lists, h.log, req.RID, req.Conn.ClientIP,
		writes, cookies)
}

/*
 * expand разворачивает подстановки в метке события: {value} -- значение куки
 * целиком, {tag} -- его читаемая половина, {name} -- имя куки. Подстановка
 * пустой строкой -- нормальный исход: правило сработало на absent, и куки
 * действительно нет.
 *
 * Метка длиннее предела модуля режется здесь: отброшенное на той стороне
 * действие унесло бы с собой весь ответ.
 */
func expand(asks []policy.Ask, values map[string]seen) ([]protocol.Action, []string) {
	if len(asks) == 0 {
		return nil, nil
	}

	var dropped []string

	out := make([]protocol.Action, 0, len(asks))

	for _, ask := range asks {
		action := ask.Action

		if action.Marker != "" && strings.ContainsRune(action.Marker, '{') {
			v := values[ask.Cookie]

			marker := strings.NewReplacer(
				"{value}", v.Value,
				"{tag}", v.Tag,
				"{name}", ask.Cookie,
			).Replace(action.Marker)

			marker = strings.TrimSpace(marker)

			if marker == "" {
				dropped = append(dropped, ask.Cookie)

				continue
			}

			if len(marker) > protocol.MarkerMax {
				marker = marker[:protocol.MarkerMax]
			}

			action.Marker = marker
		}

		out = append(out, action)
	}

	return out, dropped
}

func cookieNames(cookies []protocol.Cookie) []string {
	if len(cookies) == 0 {
		return nil
	}

	out := make([]string, 0, len(cookies))

	for _, c := range cookies {
		out = append(out, c.Name)
	}

	return out
}

func (h *handler) plain(req *protocol.Request, code string) *protocol.Reply {
	reply := protocol.NewReply(req, protocol.VerdictAllow)
	reply.Reason = &protocol.Reason{Code: code}

	return reply
}

// fallback -- ответ на сообщение, которое не разобралось: вердикт error.
func (h *handler) fallback(payload []byte, code string) *protocol.Reply {
	return protocol.FallbackReply(protocol.SniffRID(payload), h.cfg.Name, code)
}

func (h *handler) send(subject string, reply *protocol.Reply, req *protocol.Request,
	det audit.Details) {

	if subject == "" {
		h.log.Error("no reply subject in message", "rid", reply.RID)

		return
	}

	payload, err := reply.Marshal()
	if err != nil {
		h.log.Error("reply marshal failed", "rid", reply.RID, "error", err.Error())

		payload, err = protocol.FallbackReply(reply.RID, reply.Inspector,
			codeInternalError).Marshal()
		if err != nil {
			return
		}
	}

	if err := h.nc.Publish(subject, payload); err != nil {
		h.log.Error("respond failed", "rid", reply.RID, "error", err.Error())
	}

	// Аудит после inbox: волна уже получила ответ.
	if err := h.audit.Add(req, reply, det); err != nil {
		h.log.Warn("audit publish failed", "rid", reply.RID, "error", err.Error())
	}
}

// Паника внутри обработки превращается в error с кодом, а не в падение
// процесса и не в молчание, которое модуль ждёт весь дедлайн.
func (h *handler) recoverInto(subject, rid string) {
	r := recover()
	if r == nil {
		return
	}

	h.log.Error("handler panicked", "rid", rid, "panic", r, "stack", string(debug.Stack()))

	if subject == "" {
		return
	}

	h.send(subject, protocol.FallbackReply(rid, h.cfg.Name, codeInternalError),
		nil, audit.Details{})
}

/*
 * overloadOnShed -- строки перегрузки на снятом по полной очереди запросе:
 * срабатывают все, каков бы ни был порог, и только на фазе запроса
 * (internal/overload). Просьбы едут рядом с error, модуль исполнит свои
 * глаголы; записи в наборы публикует сам инспектор. Бюджета у снятого
 * запроса нет: кодер ограничен своим таймаутом.
 */
func (h *handler) overloadOnShed(t *queue.Task, shed string, reply *protocol.Reply,
	det audit.Details) int {

	if shed != queue.ReasonQueueLimit || t.Req.Phase != protocol.PhaseRequest {
		return 0
	}

	p, ok := h.store.Current().Profile(t.Req.Route.Profile)
	if !ok || p.Mode == policy.ModeOff {
		return 0
	}

	out := p.CollectOverload(t.Fill, true)

	if len(out.Rules) == 0 {
		return 0
	}

	det.Engine["rules"] = out.Rules

	if err := h.publish(context.Background(), out.Writes, nil, t.Req); err != nil {
		h.log.Error("geo unavailable for a list write", "rid", t.Req.RID,
			"profile", p.Name, "error", err.Error())

		det.Engine["geo"] = err.Error()
	}

	actions, _ := expand(out.Actions, nil)
	reply.Actions = actions

	return len(actions)
}
