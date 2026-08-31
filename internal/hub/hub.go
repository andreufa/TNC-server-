package hub

import (
	"encoding/hex"
	"log"
	"sort"
	"strings"
	"sync/atomic"
)

// Subscriber receives broadcast messages. Its C channel is buffered; if it
// fills up (slow consumer), further messages for that subscriber are dropped
// rather than blocking the whole hub.
type Subscriber struct {
	C  chan []byte
	id uint64

	// DeviceID identifies the device behind this subscriber (set when the
	// connection is subscribed, i.e. after authentication). Used to report
	// broadcast recipients in logs.
	DeviceID string
}

// Hub is a simple in-memory pub/sub broadcaster. All state is owned by the
// single Run goroutine, so no locks are needed.
type Hub struct {
	register   chan *Subscriber
	unregister chan *Subscriber
	broadcast  chan message
	quit       chan struct{}
	nextID     atomic.Uint64
	msgCount   atomic.Uint64 // total broadcast messages (monotonically increasing)
	subCount   atomic.Int64  // current number of active subscribers
}

type message struct {
	data   []byte
	sender uint64 // subscriber id of the sender; recipients with this id are skipped

	// reply delivers the result of this broadcast (sent/delivered lists).
	// Nil for internal broadcasts.
	reply chan BroadcastResult
}

// BroadcastResult reports which devices a broadcast was addressed to and
// which of them actually received it.
type BroadcastResult struct {
	// Sent — every subscriber the message was addressed to (sender excluded),
	// regardless of whether their channel accepted it.
	Sent []string
	// Delivered — the subset of Sent whose channel accepted the message.
	// Slow subscribers with a full buffer are in Sent but not in Delivered.
	Delivered []string
}

const subscriberBuffer = 64

// New creates a Hub. Call Run in a goroutine before using it.
func New() *Hub {
	return &Hub{
		register:   make(chan *Subscriber),
		unregister: make(chan *Subscriber),
		broadcast:  make(chan message),
		quit:       make(chan struct{}),
	}
}

// Run processes hub events until Stop is called. Owns the subscriber set.
func (h *Hub) Run() {
	subscribers := make(map[uint64]*Subscriber)
	for {
		select {
		case s := <-h.register:
			subscribers[s.id] = s
			h.subCount.Add(1)
		case s := <-h.unregister:
			if _, ok := subscribers[s.id]; ok {
				delete(subscribers, s.id)
				close(s.C)
				h.subCount.Add(-1)
			}
		case m := <-h.broadcast:
			h.msgCount.Add(1)
			res := BroadcastResult{
				Sent:      make([]string, 0, len(subscribers)),
				Delivered: make([]string, 0, len(subscribers)),
			}
			for id, s := range subscribers {
				if id == m.sender {
					continue // don't echo back to the sender
				}
				res.Sent = append(res.Sent, s.DeviceID)
				select {
				case s.C <- m.data:
					res.Delivered = append(res.Delivered, s.DeviceID)
				default: // slow subscriber: drop this message
				}
			}
			if m.reply != nil {
				sort.Strings(res.Sent)
				sort.Strings(res.Delivered)
				m.reply <- res
			}
		case <-h.quit:
			for _, s := range subscribers {
				close(s.C)
			}
			return
		}
	}
}

// Subscribe registers a new subscriber for the given device and returns it.
// The returned id is used with Broadcast to avoid echoing a message back to
// its sender.
func (h *Hub) Subscribe(deviceID string) *Subscriber {
	id := h.nextID.Add(1)
	s := &Subscriber{C: make(chan []byte, subscriberBuffer), id: id, DeviceID: deviceID}
	h.register <- s
	return s
}

// Unsubscribe removes a subscriber. Safe to call once per subscriber.
func (h *Hub) Unsubscribe(s *Subscriber) {
	select {
	case h.unregister <- s:
	case <-h.quit:
	}
}

// Broadcast sends data to all subscribers except the one identified by
// senderID. Pass 0 to deliver to everyone.
//
// It returns the delivery result for logging: Sent contains every device the
// message was addressed to (sender excluded); Delivered contains those whose
// channel actually accepted it. Both lists are empty if the hub is stopped.
func (h *Hub) Broadcast(data []byte, senderID uint64) BroadcastResult {
	reply := make(chan BroadcastResult, 1)
	select {
	case h.broadcast <- message{data: data, sender: senderID, reply: reply}:
	case <-h.quit:
		return BroadcastResult{}
	}
	var res BroadcastResult
	select {
	case res = <-reply:
	case <-h.quit:
		return BroadcastResult{}
	}
	log.Printf("hub: broadcast from sender %d sent to %d device(s): [%s], delivered to %d: [%s]",
		senderID, len(res.Sent), strings.Join(res.Sent, ", "),
		len(res.Delivered), strings.Join(res.Delivered, ", "))
	log.Printf("hub: msg %s", hex.EncodeToString(data))
	return res
}

// ID returns the subscriber's id, for use as senderID in Broadcast.
func (s *Subscriber) ID() uint64 { return s.id }

// MsgTotal returns the total number of broadcast messages since the hub started.
func (h *Hub) MsgTotal() uint64 { return h.msgCount.Load() }

// SubCount returns the current number of active subscribers.
func (h *Hub) SubCount() int64 { return h.subCount.Load() }

// Stop shuts down the hub and closes all subscriber channels.
func (h *Hub) Stop() { close(h.quit) }
