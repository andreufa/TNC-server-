// Асинхронное хранение измерений команды 0x59 для графиков.
package store

import (
	"context"
	"log"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"tnc-server/internal/models"
)

const (
	measurementBatchSize   = 512
	measurementFlushPeriod = 2 * time.Second
	measurementQueueSize   = 2048
)

// Point — точка графика после прореживания/агрегации. Off1..Off3 = nil
// (null в JSON — разрыв на графике), если значение отсутствует: NaN/±Inf
// в кадре или все сэмплы корзины невалидны.
type Point struct {
	Ts       int64    `json:"ts"`       // Unix-миллисекунды
	Off1     *float64 `json:"off1"`     // метры
	Off2     *float64 `json:"off2"`     // метры
	Off3     *float64 `json:"off3"`     // метры
	Validity uint32   `json:"validity"` // битовая маска (для агрегата — побитовое И)
	N        int      `json:"n"`        // исходных сэмплов в точке (1 — сырая)
}

// MeasurementStore пишет измерения в таблицу measurements асинхронно (канал +
// фоновая горутина с пакетной вставкой), чтобы не тормозить TCP-цикл
// устройств, и раз в час чистит данные старше retentionDays суток.
type MeasurementStore struct {
	pool          *pgxpool.Pool
	retentionDays int
	ch            chan models.Measurement
	quit          chan struct{}
	wg            sync.WaitGroup
	dropped       atomic.Int64
}

func NewMeasurementStore(pool *pgxpool.Pool, retentionDays int) *MeasurementStore {
	if retentionDays < 1 {
		retentionDays = 7
	}
	return &MeasurementStore{
		pool:          pool,
		retentionDays: retentionDays,
		ch:            make(chan models.Measurement, measurementQueueSize),
		quit:          make(chan struct{}),
	}
}

// Start запускает фоновые горутины вставки и очистки.
func (s *MeasurementStore) Start() {
	s.wg.Add(2)
	go s.insertLoop()
	go s.cleanupLoop()
}

// Close останавливает фоновые горутины, дописав накопленный батч.
func (s *MeasurementStore) Close() {
	select {
	case <-s.quit:
		return
	default:
	}
	close(s.quit)
	s.wg.Wait()
}

// Enqueue ставит измерение в очередь вставки. Не блокирует вызывающего:
// при переполнении очереди измерение отбрасывается (логируется раз в 100).
func (s *MeasurementStore) Enqueue(m models.Measurement) {
	select {
	case s.ch <- m:
	default:
		if s.dropped.Add(1)%100 == 0 {
			log.Printf("measurements: queue full, dropped %d total", s.dropped.Load())
		}
	}
}

func (s *MeasurementStore) insertLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(measurementFlushPeriod)
	defer ticker.Stop()
	batch := make([]models.Measurement, 0, measurementBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.insertBatch(batch); err != nil {
			log.Printf("measurements: insert batch of %d: %v", len(batch), err)
		}
		batch = batch[:0]
	}
	for {
		select {
		case m := <-s.ch:
			batch = append(batch, m)
			if len(batch) >= measurementBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.quit:
			flush()
			return
		}
	}
}

func (s *MeasurementStore) insertBatch(ms []models.Measurement) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows := make([][]any, len(ms))
	for i, m := range ms {
		rows[i] = []any{m.DeviceID, int64(m.MsgNo), m.Ts, m.ReceivedAt,
			m.Off1, m.Off2, m.Off3, int64(m.StaticCnt), int64(m.Validity)}
	}
	_, err := s.pool.CopyFrom(ctx, pgx.Identifier{"measurements"},
		[]string{"device_id", "msg_no", "ts", "received_at", "off1", "off2", "off3", "static_cnt", "validity"},
		pgx.CopyFromRows(rows))
	return err
}

func (s *MeasurementStore) cleanupLoop() {
	defer s.wg.Done()
	s.cleanup()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.quit:
			return
		}
	}
}

func (s *MeasurementStore) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM measurements WHERE received_at < now() - ($1::int * interval '1 day')`,
		s.retentionDays)
	if err != nil {
		log.Printf("measurements: cleanup: %v", err)
		return
	}
	if tag.RowsAffected() > 0 {
		log.Printf("measurements: cleanup removed %d rows older than %d days",
			tag.RowsAffected(), s.retentionDays)
	}
}

// QueryRange возвращает точки измерений устройства за интервал [from, to],
// прореженные до maxPoints (усреднение по корзинам). Порядок — по времени
// возрастания.
func (s *MeasurementStore) QueryRange(ctx context.Context, deviceID string, from, to time.Time, maxPoints int) ([]Point, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ts, off1, off2, off3, validity
		FROM measurements
		WHERE device_id = $1 AND ts >= $2 AND ts <= $3
		ORDER BY ts ASC`,
		deviceID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var raw []rawPoint
	for rows.Next() {
		var ts time.Time
		var o1, o2, o3 float64
		var validity int64
		if err := rows.Scan(&ts, &o1, &o2, &o3, &validity); err != nil {
			return nil, err
		}
		raw = append(raw, rawPoint{ts: ts, off1: o1, off2: o2, off3: o3, validity: uint32(validity)})
	}
	return downsample(raw, maxPoints), rows.Err()
}

type rawPoint struct {
	ts       time.Time
	off1     float64
	off2     float64
	off3     float64
	validity uint32
}

// downsample прореживает сырые точки до maxPoints корзин, усредняя значения
// внутри корзины. NaN/±Inf отбрасываются; если в корзине нет валидных
// значений, поле остаётся nil (разрыв на графике). Validity корзины —
// побитовое И всех сэмплов.
func downsample(raw []rawPoint, maxPoints int) []Point {
	if len(raw) == 0 {
		return []Point{}
	}
	if maxPoints <= 0 || len(raw) <= maxPoints {
		return rawToPoints(raw)
	}
	bucketSize := (len(raw) + maxPoints - 1) / maxPoints
	out := make([]Point, 0, maxPoints)
	for i := 0; i < len(raw); i += bucketSize {
		end := i + bucketSize
		if end > len(raw) {
			end = len(raw)
		}
		b := raw[i:end]
		p := Point{Ts: b[0].ts.UnixMilli(), N: len(b), Validity: ^uint32(0)}
		p.Off1 = avgOff(b, 1)
		p.Off2 = avgOff(b, 2)
		p.Off3 = avgOff(b, 3)
		for _, r := range b {
			p.Validity &= r.validity
		}
		out = append(out, p)
	}
	return out
}

func rawToPoints(raw []rawPoint) []Point {
	out := make([]Point, len(raw))
	for i, r := range raw {
		out[i] = Point{
			Ts:       r.ts.UnixMilli(),
			Off1:     f2p(r.off1),
			Off2:     f2p(r.off2),
			Off3:     f2p(r.off3),
			Validity: r.validity,
			N:        1,
		}
	}
	return out
}

// avgOff — среднее по полю off<idx> корзины; NaN/±Inf пропускаются.
func avgOff(b []rawPoint, idx int) *float64 {
	var sum float64
	n := 0
	for _, r := range b {
		v := r.off1
		switch idx {
		case 2:
			v = r.off2
		case 3:
			v = r.off3
		}
		if math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		sum += v
		n++
	}
	if n == 0 {
		return nil
	}
	avg := sum / float64(n)
	return &avg
}

// f2p конвертирует float64 в указатель; NaN/±Inf → nil (null в JSON).
func f2p(v float64) *float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	return &v
}
