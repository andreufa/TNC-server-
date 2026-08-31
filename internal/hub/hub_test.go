package hub

import (
	"reflect"
	"testing"
)

func newRunningHub(t *testing.T) *Hub {
	t.Helper()
	h := New()
	go h.Run()
	t.Cleanup(h.Stop)
	return h
}

func TestBroadcastSentAndDeliveredExcludeSender(t *testing.T) {
	h := newRunningHub(t)

	devA := h.Subscribe("DEV-A")
	devB := h.Subscribe("DEV-B")
	devC := h.Subscribe("DEV-C")

	res := h.Broadcast([]byte{1}, devB.ID())
	want := []string{"DEV-A", "DEV-C"}
	if !reflect.DeepEqual(res.Sent, want) {
		t.Fatalf("Sent = %v, want %v", res.Sent, want)
	}
	if !reflect.DeepEqual(res.Delivered, want) {
		t.Fatalf("Delivered = %v, want %v", res.Delivered, want)
	}

	// Delivered to A and C, not echoed back to the sender B.
	select {
	case <-devA.C:
	default:
		t.Fatal("DEV-A did not receive the broadcast")
	}
	select {
	case <-devB.C:
		t.Fatal("DEV-B (sender) received its own broadcast")
	default:
	}
	select {
	case <-devC.C:
	default:
		t.Fatal("DEV-C did not receive the broadcast")
	}
}

func TestBroadcastSenderZeroDeliversToAll(t *testing.T) {
	h := newRunningHub(t)
	devA := h.Subscribe("DEV-A")
	devB := h.Subscribe("DEV-B")

	res := h.Broadcast([]byte{2}, 0)
	want := []string{"DEV-A", "DEV-B"}
	if !reflect.DeepEqual(res.Sent, want) {
		t.Fatalf("Sent = %v, want %v", res.Sent, want)
	}
	if !reflect.DeepEqual(res.Delivered, want) {
		t.Fatalf("Delivered = %v, want %v", res.Delivered, want)
	}
	select {
	case <-devA.C:
	default:
		t.Fatal("DEV-A did not receive the broadcast")
	}
	select {
	case <-devB.C:
	default:
		t.Fatal("DEV-B did not receive the broadcast")
	}
}

func TestBroadcastSlowSubscriberSentButNotDelivered(t *testing.T) {
	h := newRunningHub(t)
	slow := h.Subscribe("DEV-SLOW")
	fast := h.Subscribe("DEV-FAST")

	// Fill the slow subscriber's buffer completely.
	for i := 0; i < subscriberBuffer; i++ {
		h.Broadcast([]byte{9}, fast.ID())
	}

	// Slow's channel is full: it is still addressed (Sent), but the message
	// is dropped, so it must not appear in Delivered. Fast is the sender.
	res := h.Broadcast([]byte{3}, fast.ID())
	if want := []string{"DEV-SLOW"}; !reflect.DeepEqual(res.Sent, want) {
		t.Fatalf("Sent = %v, want %v", res.Sent, want)
	}
	if len(res.Delivered) != 0 {
		t.Fatalf("Delivered = %v, want empty (slow consumer dropped)", res.Delivered)
	}
	_ = slow
}
