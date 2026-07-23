package hub

import (
	"encoding/hex"
	"log"
	"sync/atomic"
)

// Subscriber receives broadcast messages. Its C channel is buffered; if it
// fills up (slow consumer), further messages for that subscriber are dropped
// rather than blocking the whole hub.
type Subscriber struct {
	C  chan []byte
	id uint64
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
			for id, s := range subscribers {
				if id == m.sender {
					continue // don't echo back to the sender
				}
				select {
				case s.C <- m.data:
				default: // slow subscriber: drop this message
				}
			}
		case <-h.quit:
			for _, s := range subscribers {
				close(s.C)
			}
			return
		}
	}
}

// Subscribe registers a new subscriber and returns it. The returned id is used
// with Broadcast to avoid echoing a message back to its sender.
func (h *Hub) Subscribe() *Subscriber {
	id := h.nextID.Add(1)
	s := &Subscriber{C: make(chan []byte, subscriberBuffer), id: id}
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
func (h *Hub) Broadcast(data []byte, senderID uint64) {
	log.Printf("hub: broadcasting from sender %d", senderID)
	log.Printf("hub: msg %s", hex.EncodeToString(data))
	select {
	case h.broadcast <- message{data: data, sender: senderID}:
	case <-h.quit:
	}
}

// ID returns the subscriber's id, for use as senderID in Broadcast.
func (s *Subscriber) ID() uint64 { return s.id }

// MsgTotal returns the total number of broadcast messages since the hub started.
func (h *Hub) MsgTotal() uint64 { return h.msgCount.Load() }

// SubCount returns the current number of active subscribers.
func (h *Hub) SubCount() int64 { return h.subCount.Load() }

// Stop shuts down the hub and closes all subscriber channels.
func (h *Hub) Stop() { close(h.quit) }
