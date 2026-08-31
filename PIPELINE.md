# PIPELINE — Маршрут команды от фрейма до доставки

```
                          CryptoServer.handleConnection()
                         ┌────────────────────────────────┐
                         │                                │
  TCP conn ──→ FrameReader.ReadFrame()                   │
                         │                                │
                         ▼                                │
              ┌─────────────────────┐                     │
              │ Connection-level     │                     │
              │ logging (raw hex)    │                     │
              └─────────┬───────────┘                     │
                        │                                │
                        ▼                                │
              ┌─────────────────────┐                     │
              │ Handler lookup      │                     │
              │ cmd → HandlerFactory│  perConnHandlers    │
              │ (lazy, per-conn)    │  cache              │
              └─────────┬───────────┘                     │
                        │                                │
                        ▼                                │
              ╔═════════════════════╗                     │
              ║  MIDDLEWARE CHAIN   ║                     │
              ║                     ║                     │
              ║  ┌───────────────┐  ║                     │
     Frame ──╫─→│  AuthGate      │  ║  outer (runs first) │
              ║  │               │  ║                     │
              ║  │ Auth? ──no──→ drop (nil, nil)         │
              ║  │  │            │  ║                     │
              ║  │ yes           │  ║                     │
              ║  └───────┬───────┘  ║                     │
              ║          ▼          ║                     │
              ║  ┌───────────────┐  ║                     │
              ║  │  Logging      │  ║  inner              │
              ║  │               │  ║                     │
              ║  │ log dispatch  │  ║                     │
              ║  │    + result   │  ║                     │
              ║  └───────┬───────┘  ║                     │
              ║          ▼          ║                     │
              ║  ┌───────────────┐  ║                     │
              ║  │  Handler      │  ║  business logic     │
              ║  │  .Handle()    │  ║                     │
              ║  └───────┬───────┘  ║                     │
              ║          │          ║                     │
              ╚══════════╪══════════╝                     │
                         │ *Message                       │
                         ▼                                │
              ┌─────────────────────┐                     │
              │ switch msg.Mode:    │                     │
              │                     │                     │
              │ DeliverNone ──→ skip                      │
              │ DeliverBroadcast → Hub.Broadcast()        │
              │ DeliverUnicast ──→ conn.Write()           │
              │ DeliverDirect ───→ (fallback broadcast)   │
              └─────────┬───────────┘                     │
                        │                                │
                        ▼ (broadcast)                    │
              ┌─────────────────────┐                     │
              │ Hub                 │                     │
              │ pub/sub (all subs   │                     │
              │ except sender)      │                     │
              └─────────┬───────────┘                     │
                        │                                │
                        ▼                                │
              ┌─────────────────────┐                     │
              │ Subscriber goroutine│                     │
              │ Frame → conn.Write  │                     │
              └─────────────────────┘                     │
                                                        │
                         └────────────────────────────────┘
```

## Ключевые компоненты

### 1. Реестр (`internal/cmd/registry.go`)

Глобальная map `map[byte]HandlerFactory`. Пакеты команд регистрируются через `init()`:

```go
func init() {
    cmd.Register(tcp.CmdRegular, func() tcp.CmdHandler { return &Handler{} })
}
```

`main.go` получает снимок реестра через `cmd.GetAll()` и передаёт в `CryptoServer`.

**Добавление новой команды**:
1. `internal/cmd/cmd0xNN/handler.go` — реализовать `tcp.CmdHandler`
2. `init()` с `cmd.Register(0xNN, factory)`
3. `cmd/server/main.go` — `_ "tnc-server/internal/cmd/cmd0xNN"`

### 2. Middleware (`internal/cmd/middleware.go`)

Цепочка `Middleware func(CmdHandler) CmdHandler`. Применяется через `Pipeline()`:

```
Pipeline(rawHandler, AuthGate(), Logging())
```

Порядок: первый аргумент — outermost, последний — ближе к handler'у.

| Middleware  | Позиция   | Что делает |
|-------------|-----------|------------|
| `AuthGate`  | outermost | Блокирует все команды кроме `0x65` до аутентификации |
| `Logging`   | inner     | Логирует dispatch и результат handler'а |

**Добавление нового middleware**: реализовать `Middleware`, добавить в вызов `Pipeline()` в `crypto_server.go`.

### 3. Message (`internal/tcp/message.go`)

Типизированный контракт handler → сервер:

```go
type Message struct {
    Mode    DeliveryMode  // что делать: broadcast, unicast, none
    Addr    byte          // адресный байт (0x70 для broadcast)
    Cmd     byte          // команда
    Payload []byte        // данные команды
    Targets []string      // для DeliverDirect (будущее)
}
```

`WireBytes()` сериализует в `[Addr|Cmd|Payload]` — стабильный формат для Hub.

## Пример: путь команды 0x59

```
1. Device отправляет:  $ | 0x76 | 0x59 | len(44) | 44 bytes | CRC
2. FrameReader.ReadFrame() → Frame{Addr:0x76, Cmd:0x59, Data:[44 байта]}
3. Connection-level log: "[192.168.1.5] frame from DEV001: Addr=0x76 Cmd=0x59"
4. Handler lookup: registry[0x59] → cmd0x59.Handler factory
5. Pipeline(raw, AuthGate(), Logging())
6. AuthGate: ctx.Authenticated=true → pass
7. Logging: "cmd: dispatching Cmd=0x59 Addr=0x76 device=DEV001"
8. cmd0x59.Handle():
   - fr.Addr == 0x76 ✓
   - return &Message{Mode:DeliverBroadcast, Addr:0x70, Cmd:0x59, Payload:fr.Data}
9. Logging: "cmd: Cmd=0x59 → DeliverBroadcast (addr=0x70 payload=44 bytes)"
 10. CryptoServer:
     - msg.Mode == DeliverBroadcast
     - wireBytes = msg.WireBytes() → [0x70, 0x59, 44 bytes]
     - res = hub.Broadcast(wireBytes, senderID) → {Sent, Delivered}
     - консоль + web-лог: "sent [DEV002, DEV003] delivered [DEV002]"
 11. Hub: доставляет wireBytes всем подписчикам кроме отправителя и возвращает BroadcastResult{Sent, Delivered} (Sent — адресовано, Delivered — попало в канал)
12. Subscriber goroutine:
    - парсит [0x70, 0x59, payload]
    - Frame{Addr:0x70, Cmd:0x59, Data:payload}
    - EncodeFrame → conn.Write → устройство получает broadcast
```

## Пример: путь команды 0x65 (auth)

```
1. Device отправляет param request: $ | 0x61 | 0x65 | len(14) | DID | CRC
2. AuthGate: ctx.Authenticated=false, but fr.Cmd == CmdAuth → pass
3. Logging: "cmd: dispatching Cmd=0x65 Addr=0x61 device="
4. cmd0x65.Handle() → stepWaitParam:
   - handleParamRequest():
     - проверяет DID, наличие в БД, статус in-service
     - генерирует challenge
     - conn.Write(challenge frame) напрямую
     - return nil, nil (DeliverNone)
5. Logging: no error, msg == nil
6. CryptoServer: msg == nil → skip delivery
7. h.step = stepWaitAuth

... device sends auth frame ...

8. AuthGate: pass (CmdAuth)
9. cmd0x65.Handle() → stepWaitAuth:
   - handleAuth():
     - проверяет подпись, TTL, DID
     - conn.Write(StatusOK + StatusAuthorized) напрямую
     - ctx.Authenticated = true
     - return nil, nil
10. CryptoServer: ctx.Authenticated && !subscribed → subscribe to Hub
```

## Детали реализации

### Почему HandlerFactory, а не singletons

`cmd0x65` (авторизация) — **stateful**: хранит `step`, `deviceID`, `challenge`.
Один экземпляр на все соединения привёл бы к гонке данных. `HandlerFactory`
создаёт **новый** экземпляр для каждого соединения при первом обращении к
команде (`perConnHandlers` в `crypto_server.go`).

### Почему middleware применяется лениво

Middleware оборачивает handler при первом использовании команды **на этом
соединении** (`perConnHandlers`).  Это даёт:
- Один экземпляр middleware-цепочки на команду на соединение (экономия)
- Гарантию, что stateful handler создан фабрикой один раз

### Hub: без изменений

Hub продолжает работать с `[]byte` (формат `[Addr|Cmd|Payload]`). Новый слой
`Message` → `WireBytes()` находится **выше** Hub. Это сознательное решение:
- Hub — чистый транспорт, не должен знать о семантике сообщений
- Если в будущем Hub получит routing/topic — достаточно изменить
  `CryptoServer` (switch msg.Mode), Hub не трогаем
