// Package ntp — часы, дисциплинированные по NTP.
//
// Фоновая горутина раз в interval опрашивает список NTP-серверов, берёт
// медиану offset (NTP − локальное) и линейной аппроксимацией (МНК) по
// последним замерам оценивает уход локальных часов. Clock.Now() возвращает
// время с поправкой offset + slope·Δt; Δt отсчитывается по монотонным часам,
// поэтому поправка устойчива к скачкам системного времени между
// синхронизациями, а точность между раундами поддерживает именно оценка
// ухода, а не частота опроса.
//
// Пока не было ни одной успешной синхронизации, Now()/Correct() возвращают
// системное время (offset = 0). При сбое очередного раунда сохраняется
// последняя известная оценка.
package ntp

import (
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/beevik/ntp"
)

// state — мгновенное состояние поправки часов.
type state struct {
	offset time.Duration // поправка (NTP − локальное) на момент ref
	slope  float64       // уход локальных часов относительно NTP, с/с
	ref    time.Time     // локальный момент, к которому относится offset (монотонный)
}

// sample — один замер offset.
type sample struct {
	at  time.Time     // локальное время замера
	off time.Duration // offset: NTP − локальное
}

// queryFunc — точка запроса к одному NTP-серверу (заменяется в тестах).
type queryFunc func(server string, timeout time.Duration) (time.Duration, error)

// maxSamples — число последних замеров для аппроксимации ухода.
const maxSamples = 8

// Clock — NTP-дисциплинированные часы.
type Clock struct {
	servers  []string
	interval time.Duration
	timeout  time.Duration
	query    queryFunc

	st      atomic.Value // *state; nil, пока нет ни одного успешного замера
	mu      sync.Mutex   // защищает samples
	samples []sample

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewClock создаёт часы. Синхронизация начинается после Start.
func NewClock(servers []string, interval, timeout time.Duration) *Clock {
	if len(servers) == 0 {
		servers = []string{
			"ntp1.vniiftri.ru", "ntp2.vniiftri.ru", "ntp3.vniiftri.ru",
			"ntp4.vniiftri.ru", "ntp21.vniiftri.ru",
		}
	}
	if interval <= 0 {
		interval = time.Minute
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Clock{
		servers:  servers,
		interval: interval,
		timeout:  timeout,
		query:    queryNTP,
		quit:     make(chan struct{}),
	}
}

// Start запускает фоновую синхронизацию: немедленный раунд при старте,
// далее — раз в interval.
func (c *Clock) Start() {
	c.wg.Add(1)
	go c.loop()
}

// Stop останавливает фоновую синхронизацию и ждёт завершения горутины.
func (c *Clock) Stop() {
	select {
	case <-c.quit:
	default:
		close(c.quit)
	}
	c.wg.Wait()
}

func (c *Clock) loop() {
	defer c.wg.Done()
	c.sync()
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.sync()
		case <-c.quit:
			return
		}
	}
}

// sync — один раунд: опрос всех серверов, медиана offset, обновление оценки.
func (c *Clock) sync() {
	var offs []time.Duration
	for _, srv := range c.servers {
		off, err := c.query(srv, c.timeout)
		if err != nil {
			log.Printf("ntp: %s: %v", srv, err)
			continue
		}
		offs = append(offs, off)
	}
	if len(offs) == 0 {
		log.Printf("ntp: sync round failed: none of %d server(s) responded", len(c.servers))
		return
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	med := offs[len(offs)/2] // медиана отсекает выбросы и сетевую асимметрию
	c.addSample(sample{at: time.Now(), off: med})
	log.Printf("ntp: synced: offset=%s (median of %d/%d servers)", med, len(offs), len(c.servers))
}

// addSample добавляет замер и пересчитывает поправку (линейная аппроксимация).
func (c *Clock) addSample(s sample) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.samples = append(c.samples, s)
	if len(c.samples) > maxSamples {
		c.samples = c.samples[1:]
	}
	off, slope := fit(c.samples)
	c.st.Store(&state{offset: off, slope: slope, ref: c.samples[len(c.samples)-1].at})
}

// Now возвращает текущее время с NTP-поправкой.
func (c *Clock) Now() time.Time {
	return c.Correct(time.Now())
}

// Correct применяет текущую поправку к произвольному моменту времени.
func (c *Clock) Correct(t time.Time) time.Time {
	st, _ := c.st.Load().(*state)
	if st == nil {
		return t // синхронизации ещё не было — системное время
	}
	return t.Add(st.offset + time.Duration(st.slope*float64(t.Sub(st.ref))))
}

// fit — линейная аппроксимация offset(t) = offset + slope·(t − ref) по МНК,
// где ref — момент последнего замера. Возвращает offset на момент ref и slope.
func fit(ss []sample) (time.Duration, float64) {
	if len(ss) == 0 {
		return 0, 0
	}
	if len(ss) < 2 {
		return ss[len(ss)-1].off, 0
	}
	ref := ss[len(ss)-1].at
	n := float64(len(ss))
	var sx, sy, sxx, sxy float64
	for _, s := range ss {
		x := s.at.Sub(ref).Seconds()
		y := s.off.Seconds()
		sx += x
		sy += y
		sxx += x * x
		sxy += x * y
	}
	denom := n*sxx - sx*sx
	slope := 0.0
	if denom != 0 {
		slope = (n*sxy - sx*sy) / denom
	}
	intercept := (sy - slope*sx) / n
	return time.Duration(intercept * float64(time.Second)), slope
}

// queryNTP — реальный запрос к одному NTP-серверу (SNTP, UDP:123).
func queryNTP(server string, timeout time.Duration) (time.Duration, error) {
	resp, err := ntp.QueryWithOptions(server, ntp.QueryOptions{Timeout: timeout})
	if err != nil {
		return 0, err
	}
	if err := resp.Validate(); err != nil {
		return 0, err
	}
	return resp.ClockOffset, nil
}
