/*
 * Записи правил профиля в живые наборы.
 *
 * Пишется одно из двух: субъект запроса -- адрес клиента как есть, анонсы
 * (net -- эффективный, net_all -- все накрывающие) и состав системы (asn) у
 * кодера -- либо значение самой куки. Второе и есть то, ради чего инспектор
 * куки умеет писать наборы: край сверяет значение быстрым путём
 * (waf_local_check <набор> $waf_request_cookies.<имя>), не спрашивая шину.
 *
 * Анонсы и состав системы спрашиваются синхронно, в бюджете сообщения: модулю
 * всё равно ждать инспектора, а «пусто на первом запросе» -- это молча
 * несостоявшаяся запись. Сама запись уходит keeper в фоне, одним кадром на
 * строку: и адрес, и сотни префиксов системы -- вся пачка или никак.
 *
 * Ошибка -- только от кодера: строка требует анонс или состав системы, а кодер
 * молчит либо его нет. Вызывающий отвечает error, а что делать с запросом,
 * решает waf_exception маршрута. Так же отвечают капча и остальные
 * отправители. Строки, которым кодер не нужен, пишутся всё равно: ни адрес, ни
 * значение куки от него не зависят.
 */

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/exemt/placitum-shared/netinfo"
	"github.com/exemt/placitum-cookie/internal/policy"
)

/*
 * Кодер и наборы -- за интерфейсами, чтобы путь записи проверялся без шины и
 * без gRPC. Боевые реализации -- netinfo.Resolver и dataset.Publisher; обе
 * nil-безопасны: nil-кодер отвечает «недоступен», nil-набор молчит.
 */
type geoWriter interface {
	Write(ctx context.Context, write, addr string) ([]string, error)
}

type listWriter interface {
	AddMany(name string, values []string, ttl time.Duration, reason string) error
	Remove(name, value, reason string) error
}

func writeLists(ctx context.Context, geo geoWriter, lists listWriter, log *slog.Logger,
	rid, addr string, writes []policy.Write, cookies map[string]string) error {

	var failed error

	for _, w := range writes {
		values, err := subjects(ctx, geo, log, rid, addr, w, cookies)
		if err != nil {
			if failed == nil {
				failed = err
			}

			continue
		}

		if len(values) == 0 {
			continue
		}

		if w.Op == policy.OpRemove {
			/*
			 * Снятие идёт по одному значению: пачки у remove нет, а
			 * значений в снятии почти всегда одно -- кука либо адрес.
			 * Отсутствующего keeper снимает как no-op и отвечает ok.
			 */
			for _, v := range values {
				if err := lists.Remove(w.List, v, w.Reason); err != nil {
					log.Warn("list remove failed", "rid", rid, "set", w.List,
						"error", err.Error())
				}
			}

			continue
		}

		if err := lists.AddMany(w.List, values, w.TTL, w.Reason); err != nil {
			log.Warn("list publish failed", "rid", rid, "set", w.List, "error", err.Error())
		}
	}

	return failed
}

/*
 * subjects -- что именно уедет в набор этой строкой. Пустой список означает
 * «писать нечего, и это не ошибка»: кодер не знает адреса, куки на запросе не
 * оказалось, сообщение пробы пришло без адреса.
 */
func subjects(ctx context.Context, geo geoWriter, log *slog.Logger, rid, addr string,
	w policy.Write, cookies map[string]string) ([]string, error) {

	if w.Subject == policy.WriteCookie {
		value := cookies[w.Cookie]

		if value == "" {
			/*
			 * Куки нет и не выдана -- писать нечего. Это обычный исход
			 * правила, которое сработало не на выдаче: строка с write:
			 * cookie в нём просто не о чем.
			 */
			log.Debug("list write skipped: no cookie value",
				"rid", rid, "set", w.List, "cookie", w.Cookie)

			return nil, nil
		}

		return []string{value}, nil
	}

	// Сообщение пробы приходит без адреса: писать некого.
	if addr == "" {
		return nil, nil
	}

	if !netinfo.Networked(w.Subject) {
		return []string{addr}, nil
	}

	got, err := geo.Write(ctx, w.Subject, addr)
	if err != nil {
		return nil, err
	}

	if len(got) == 0 {
		log.Warn("list write skipped: coder knows nothing about the address",
			"rid", rid, "set", w.List, "write", w.Subject, "addr", addr)

		return nil, nil
	}

	return got, nil
}
