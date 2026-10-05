package store

import (
	"math"
	"testing"
	"time"
)

func raw(ms int64, o1, o2, o3 float64, v uint32) rawPoint {
	// Имитация приёма сервером через 5 с после времени устройства.
	return rawPoint{ts: time.UnixMilli(ms), receivedAt: time.UnixMilli(ms + 5000), off1: o1, off2: o2, off3: o3, validity: v}
}

func TestDownsampleIdentity(t *testing.T) {
	raws := []rawPoint{
		raw(1000, 1, 2, 3, 0b111),
		raw(2000, 4, 5, 6, 0b101),
	}
	pts := downsample(raws, 100)
	if len(pts) != 2 {
		t.Fatalf("len = %d, want 2", len(pts))
	}
	if pts[0].Ts != 1000 || *pts[0].Off1 != 1 || pts[0].N != 1 {
		t.Errorf("point 0 = %+v", pts[0])
	}
	if pts[0].ReceivedAt != 6000 {
		t.Errorf("point 0 ReceivedAt = %d, want 6000", pts[0].ReceivedAt)
	}
	if pts[1].Validity != 0b101 {
		t.Errorf("point 1 validity = %b, want 0b101", pts[1].Validity)
	}
}

func TestDownsampleNaNBecomesNil(t *testing.T) {
	pts := downsample([]rawPoint{raw(1000, math.NaN(), 5, math.Inf(1), 0b111)}, 100)
	if len(pts) != 1 {
		t.Fatalf("len = %d, want 1", len(pts))
	}
	if pts[0].Off1 != nil {
		t.Error("Off1 должен быть nil для NaN")
	}
	if pts[0].Off2 == nil || *pts[0].Off2 != 5 {
		t.Error("Off2 должен сохраниться")
	}
	if pts[0].Off3 != nil {
		t.Error("Off3 должен быть nil для Inf")
	}
}

func TestDownsampleBuckets(t *testing.T) {
	raws := []rawPoint{
		raw(1000, 1, 10, 100, 0b111),
		raw(2000, 3, 10, 100, 0b111),
		raw(3000, 5, 20, 200, 0b011),
		raw(4000, 7, 20, 200, 0b011),
		raw(5000, 9, 30, 300, 0b001),
	}
	pts := downsample(raws, 2) // 5 точек → корзины по 3: [1,2,3] и [4,5]
	if len(pts) != 2 {
		t.Fatalf("len = %d, want 2", len(pts))
	}
	// Корзина 1: средние (1+3+5)/3=3, (10+10+20)/3≈13.333, (100+100+200)/3≈133.333
	if *pts[0].Off1 != 3 {
		t.Errorf("bucket1 off1 = %v, want 3", *pts[0].Off1)
	}
	if math.Abs(*pts[0].Off2-40.0/3) > 1e-9 {
		t.Errorf("bucket1 off2 = %v, want 40/3", *pts[0].Off2)
	}
	if pts[0].Ts != 1000 || pts[0].N != 3 {
		t.Errorf("bucket1 ts/n = %d/%d, want 1000/3", pts[0].Ts, pts[0].N)
	}
	if pts[0].ReceivedAt != 6000 {
		t.Errorf("bucket1 ReceivedAt = %d, want 6000", pts[0].ReceivedAt)
	}
	if pts[0].Validity != 0b011 {
		t.Errorf("bucket1 validity = %b, want 0b011", pts[0].Validity)
	}
	// Корзина 2: (7+9)/2=8, (20+30)/2=25, (200+300)/2=250
	if *pts[1].Off1 != 8 || *pts[1].Off3 != 250 {
		t.Errorf("bucket2 off1/off3 = %v/%v, want 8/250", *pts[1].Off1, *pts[1].Off3)
	}
	if pts[1].N != 2 {
		t.Errorf("bucket2 n = %d, want 2", pts[1].N)
	}
	if pts[1].Validity != 0b001 {
		t.Errorf("bucket2 validity = %b, want 0b001", pts[1].Validity)
	}
}

func TestDownsampleEmpty(t *testing.T) {
	pts := downsample(nil, 100)
	if pts == nil || len(pts) != 0 {
		t.Errorf("пустые данные → пустой срез, got %#v", pts)
	}
}

func TestDownsampleAllNaN(t *testing.T) {
	pts := downsample([]rawPoint{
		raw(1000, math.NaN(), math.NaN(), math.NaN(), 0),
		raw(2000, math.NaN(), math.NaN(), math.NaN(), 0),
	}, 1)
	if len(pts) != 1 {
		t.Fatalf("len = %d, want 1", len(pts))
	}
	if pts[0].Off1 != nil || pts[0].Off2 != nil || pts[0].Off3 != nil {
		t.Errorf("все NaN → все nil, got %+v", pts[0])
	}
	if pts[0].N != 2 {
		t.Errorf("n = %d, want 2", pts[0].N)
	}
}

func TestApplyValidity(t *testing.T) {
	// validity=0b101: бит 1 сброшен → iekf_hw_offset_2 невалиден (NaN).
	p := applyValidity(raw(1000, 1, 2, 3, 0b101))
	if p.off1 != 1 || p.off3 != 3 {
		t.Errorf("валидные слоты должны сохраниться: %+v", p)
	}
	if !math.IsNaN(p.off2) {
		t.Errorf("off2 должен стать NaN, got %v", p.off2)
	}
	if p.validity != 0b101 {
		t.Errorf("validity не должен меняться, got %b", p.validity)
	}

	// Невалидный слот не попадает на график: null в JSON.
	pts := downsample([]rawPoint{p}, 100)
	if len(pts) != 1 {
		t.Fatalf("len = %d, want 1", len(pts))
	}
	if pts[0].Off1 == nil || *pts[0].Off1 != 1 {
		t.Errorf("Off1 должен остаться, got %v", pts[0].Off1)
	}
	if pts[0].Off2 != nil {
		t.Errorf("Off2 должен быть nil (невалиден), got %v", *pts[0].Off2)
	}

	// Все биты валидности установлены → значения сохраняются.
	p2 := applyValidity(raw(2000, 4, 5, 6, 0b111))
	if p2.off1 != 4 || p2.off2 != 5 || p2.off3 != 6 {
		t.Errorf("0b111 должен сохранить все слоты: %+v", p2)
	}
}
