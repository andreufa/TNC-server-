package ntp

import (
	"errors"
	"testing"
	"time"
)

func TestFitSingleSample(t *testing.T) {
	off, slope := fit([]sample{{at: time.Now(), off: 5 * time.Millisecond}})
	if off != 5*time.Millisecond || slope != 0 {
		t.Fatalf("fit single: off=%v slope=%v", off, slope)
	}
}

func TestFitKnownDrift(t *testing.T) {
	// offset линейно убывает на 2 мс за 100 с → slope = −20 мкс/с.
	base := time.Now()
	var ss []sample
	for i := 0; i < 4; i++ {
		ss = append(ss, sample{
			at:  base.Add(time.Duration(i) * 100 * time.Second),
			off: 10*time.Millisecond - time.Duration(i)*2*time.Millisecond,
		})
	}
	off, slope := fit(ss)
	if d := slope - (-20e-6); d > 1e-9 || d < -1e-9 {
		t.Fatalf("slope=%v, want %v", slope, -20e-6)
	}
	// offset на момент последнего замера: 10мс − 3·2мс = 4мс.
	if d := off - 4*time.Millisecond; d > time.Microsecond || d < -time.Microsecond {
		t.Fatalf("off=%v, want ~4ms", off)
	}
}

func TestCorrectAppliesOffsetAndSlope(t *testing.T) {
	c := NewClock(nil, time.Minute, time.Second)
	base := time.Now()
	// Два замера: offset 10 мс в момент base, 9.5 мс через 50 с → slope −10 мкс/с.
	c.addSample(sample{at: base, off: 10 * time.Millisecond})
	c.addSample(sample{at: base.Add(50 * time.Second), off: 9500 * time.Microsecond})

	// На момент последнего замера поправка ≈ 9.5 мс.
	got := c.Correct(base.Add(50 * time.Second)).Sub(base.Add(50 * time.Second))
	if d := got - 9500*time.Microsecond; d > time.Microsecond || d < -time.Microsecond {
		t.Fatalf("correct at ref: got %v, want ~9.5ms", got)
	}
	// Через 100 с после последнего замера уход добавляет 100 с · 10 мкс/с = 1 мс.
	got = c.Correct(base.Add(150 * time.Second)).Sub(base.Add(150 * time.Second))
	if d := got - 8500*time.Microsecond; d > 2*time.Microsecond || d < -2*time.Microsecond {
		t.Fatalf("correct at +100s: got %v, want ~8.5ms", got)
	}
}

func TestCorrectBeforeFirstSync(t *testing.T) {
	c := NewClock(nil, time.Minute, time.Second)
	fixed := time.Unix(1000, 0)
	if got := c.Correct(fixed); !got.Equal(fixed) {
		t.Fatalf("correct without sync: got %v, want unchanged", got)
	}
}

func TestSyncMedianAndFallback(t *testing.T) {
	// Серверы вернули 1 мс, 300 мс (выброс), 2 мс → медиана 2 мс.
	offs := []time.Duration{1 * time.Millisecond, 300 * time.Millisecond, 2 * time.Millisecond}
	c := NewClock([]string{"srv1", "srv2", "srv3"}, time.Minute, time.Second)
	c.query = func(string, time.Duration) (time.Duration, error) {
		off := offs[0]
		offs = offs[1:]
		return off, nil
	}
	c.sync()

	fixed := time.Unix(1000, 0)
	if got := c.Correct(fixed).Sub(fixed); got != 2*time.Millisecond {
		t.Fatalf("after sync: offset=%v, want 2ms", got)
	}

	// Сбойный раунд: все серверы недоступны — поправка сохраняется.
	c.query = func(string, time.Duration) (time.Duration, error) { return 0, errors.New("down") }
	c.sync()
	if got := c.Correct(fixed).Sub(fixed); got != 2*time.Millisecond {
		t.Fatalf("after failed round: offset=%v, want 2ms (сохранена последняя оценка)", got)
	}
}
