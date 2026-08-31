# TCP Authorization — TNC-server

> Полная документация логики авторизации TCP-соединений устройств по протоколу ROS MP ↔ APCS.

---

## Оглавление

1. [Обзор архитектуры](#1-обзор-архитектуры)
2. [Бинарный фреймовый протокол (канальный уровень)](#2-бинарный-фреймовый-протокол-канальный-уровень)
3. [Ключевые константы и адреса](#3-ключевые-константы-и-адреса)
4. [Жизненный цикл TCP-соединения](#4-жизненный-цикл-tcp-соединения)
5. [Middleware-пайплайн (AuthGate + Logging)](#5-middleware-пайплайн-authgate--logging)
6. [Конечный автомат авторизации (команда 0x65)](#6-конечный-автомат-авторизации-команда-0x65)
7. [Криптографические операции](#7-криптографические-операции)
8. [Взаимодействие с базой данных (DeviceStore)](#8-взаимодействие-с-базой-данных-devicestore)
9. [Hub: pub/sub после авторизации](#9-hub-pubsub-после-авторизации)
10. [Регистрация обработчиков команд (Registry)](#10-регистрация-обработчиков-команд-registry)
11. [Код: все классы и функции](#11-код-все-классы-и-функции)

---

## 1. Обзор архитектуры

```
                           CryptoServer
                          ┌──────────────────────────────────────────────────────┐
   Устройство ──TCP──→    │  handleConnection()                                   │
                          │    │                                                  │
                          │    ├─ FrameReader.ReadFrame()  ← читает бинарные фреймы│
                          │    │                                                  │
                          │    ├─ Pipeline (Middleware):                          │
                          │    │    AuthGate() → Logging() → CmdHandler.Handle()  │
                          │    │       │            │             │               │
                          │    │    ┌──┴──┐    ┌───┴───┐   ┌─────┴─────┐         │
                          │    │    │Блок │    │  Лог  │   │ cmd0x65   │         │
                          │    │    │до   │    │диспетч│   │ Handler   │         │
                          │    │    │аут-и│    │+рез-та│   │ (конечный │         │
                          │    │    │зации│    │       │   │  автомат) │         │
                          │    │    └─────┘    └───────┘   └─────┬─────┘         │
                          │    │                                │               │
                          │    │                         DeviceStore (БД)        │
                          │    │                         Crypto (RSA)            │
                          │    │                                │               │
                          │    ├─ После аутентификации: подписка на Hub          │
                          │    ├─ Распределение Message по DeliveryMode          │
                          │    └─ UpdateLastSeen()                               │
                          └──────────────────────────────────────────────────────┘
```

Сервер слушает TCP-порт (по умолчанию `:9001`). Каждое соединение обрабатывается в отдельной горутине.
До успешной аутентификации устройство может отправлять только команду `0x65` (AT Authorization).
После аутентификации (`ctx.Authenticated = true`) разрешены все зарегистрированные команды.

---

## 2. Бинарный фреймовый протокол (канальный уровень)

Каждый кадр (фрейм) имеет фиксированную структуру:

| Смещение | Размер | Поле       | Описание                                      |
|----------|--------|------------|-----------------------------------------------|
| 0        | 1      | Preamble   | `$` (0x24) — маркер начала фрейма            |
| 1        | 1      | Addr+Spec  | Адрес/спецификатор (назначение фрейма)        |
| 2        | 1      | Cmd        | Номер команды (0x65 = авторизация)            |
| 3–4      | 2      | DataLen    | Длина данных (little-endian, максимум 1024)   |
| 5–N      | var    | Data       | Полезная нагрузка                             |
| N+1      | 1      | CRC        | XOR всех предшествующих байт                  |

**Минимальный фрейм**: 6 байт (заголовок + CRC, без данных).  
**Максимальный фрейм**: 6 + 1024 = 1030 байт.

### Код: `internal/tcp/frame.go`

- **`Frame`** — структура с полями `Addr`, `Cmd`, `Data`.
- **`EncodeFrame(f Frame) []byte`** — сериализует Frame в бинарный формат, вычисляет CRC.
- **`DecodeFrame(raw []byte) (Frame, error)`** — парсит бинарный буфер, проверяет preamble, длину, CRC.
- **`crcCalc(buf []byte) byte`** — вычисляет XOR-контрольную сумму.
- **`FrameReader`** — обёртка над `bufio.Reader`, реализующая `ReadFrame()` с поиском preamble.

---

## 3. Ключевые константы и адреса

### Адреса для команды `0x65` (авторизация)

| Константа              | Значение | Назначение                                         |
|------------------------|----------|----------------------------------------------------|
| `AddrParamRequest`     | `0x61`   | Устройство → Сервер: запрос параметров (DID)       |
| `AddrAuthCommand`      | `0x60`   | Устройство → Сервер: авторизация (DID + подпись)   |
| `AddrServerStatus`     | `0x63`   | Сервер → Устройство: статус-ответ                  |
| `AddrChallengeResponse`| `0x64`   | Сервер → Устройство: challenge (nonce + timestamp) |

### Адреса для команды `0x59` (регулярные сообщения)

| Константа           | Значение | Назначение                                      |
|---------------------|----------|-------------------------------------------------|
| `AddrDeviceRegular` | `0x76`   | Устройство → Сервер: данные                     |
| `AddrBroadcast`     | `0x70`   | Сервер → Устройства: broadcast (трансляция)     |

### Статус-коды (сервер → устройство)

| Константа               | Значение | Описание                                |
|-------------------------|----------|-----------------------------------------|
| `StatusOK`              | `0x00`   | Входное сообщение обработано успешно    |
| `StatusAuthorized`      | `0x01`   | Команда выполнена (авторизация ОК)      |
| `StatusAddrError`       | `0x02`   | Ошибка адреса                           |
| `StatusSpecError`       | `0x03`   | Ошибка спецификатора                    |
| `StatusNumberError`     | `0x04`   | Ошибка номера                           |
| `StatusDataLenError`    | `0x05`   | Ошибка длины поля данных                |
| `StatusDataValueError`  | `0x06`   | Ошибка значения поля данных             |
| `StatusIntegrityError`  | `0x07`   | Ошибка целостности (CRC)                |
| `StatusTimeoutError`    | `0x08`   | Ошибка таймаута обработки               |
| `StatusSeqError`        | `0x09`   | Ошибка последовательности команд        |
| `StatusCmdExecError`    | `0x0A`   | Ошибка выполнения команды               |

### Константы авторизации

| Константа              | Значение | Описание                                   |
|------------------------|----------|--------------------------------------------|
| `CmdAuth`              | `0x65`   | Номер команды авторизации                  |
| `DeviceIDSize`         | 14       | Фиксированный размер Device ID в байтах    |
| `AuthProtocolVersion`  | `0x01`   | Версия протокола авторизации               |
| `ChallengeSize`        | 32       | Размер nonce в байтах                      |
| `TimestampSize`        | 8        | Размер timestamp в байтах (Unix ms)        |
| `ChallengeTTL`         | 5 мин    | Время жизни challenge                      |

---

## 4. Жизненный цикл TCP-соединения

### 4.1 Приём соединения

```
CryptoServer.ListenAndServe()
  └─ net.Listen("tcp", addr)
  └─ for { conn := ln.Accept() → go handleConnection(conn) }
```

### 4.2 Цикл чтения фреймов (`handleConnection`)

```
handleConnection(conn):
  1. Создать FrameReader
  2. Создать CmdContext (пока DeviceID="", Authenticated=false)
  3. Цикл:
     a. conn.SetReadDeadline(now + 5 мин)     ← idle timeout
     b. fr, raw := frameReader.ReadFrame()    ← ожидание фрейма (CRC проверен)
     c. Логирование raw-фрейма
     d. UpdateLastSeen() — только для авторизованных устройств:
        после авторизации любой фрейм с корректным CRC обновляет время
        последнего сообщения (DID берётся из ctx.DeviceID). Фрейм,
        завершающий авторизацию, фиксируется в обработчике 0x65
     e. Поиск/создание per-connection handler через registry
     f. Оборачивание в middleware: Pipeline(handler, AuthGate(), Logging())
     g. msg, err := handler.Handle(fr, conn, ctx)
     h. Если ошибка ДО аутентификации → закрыть соединение
     i. Если ошибка ПОСЛЕ аутентификации → продолжить (не разрывать)
     j. Если ctx.Authenticated && !subscribed → подписаться на Hub
     k. Распределение Message по DeliveryMode (Broadcast/Unicast/Direct)
```

**Важно**: idle-таймаут 5 минут. Если устройство не шлёт фреймы дольше — соединение закрывается.

### 4.3 CmdContext

```go
// internal/tcp/handler.go
type CmdContext struct {
    Devices       *store.DeviceStore  // доступ к БД устройств
    Hub           *hub.Hub            // pub/sub хаб
    LogChan       chan<- string       // канал для web-логов
    DeviceID      string              // ID устройства (заполняется при param-запросе)
    Authenticated bool                // true после успешной авторизации
}
```

`Authenticated` — критический флаг. Именно он управляет поведением `AuthGate` и разрешает подписку на Hub.

---

## 5. Middleware-пайплайн (AuthGate + Logging)

### 5.1 Pipeline

```go
func Pipeline(handler CmdHandler, mws ...Middleware) CmdHandler
```

Применяет middleware от внешнего к внутреннему:
```
mw1 → mw2 → mw3 → handler
```

В CryptoServer используется так:
```go
handler = Pipeline(raw, AuthGate(), Logging())
// AuthGate — внешний, Logging — внутренний.
```

### 5.2 AuthGate (`middleware.go`)

**Назначение**: блокировать все команды, кроме `0x65`, до завершения авторизации.

```
Фрейм → AuthGate → ctx.Authenticated?
                      ├─ да → передать следующему (Logging → Handler)
                      └─ нет → fr.Cmd == 0x65?
                                  ├─ да → передать (это сама авторизация)
                                  └─ нет → отбросить фрейм (вернуть nil)
```

**Ключевое**: `AuthGate` — внешний middleware, срабатывает первым. Без него незащищённое устройство могло бы слать любые команды.

### 5.3 Logging (`middleware.go`)

Логирует диспетчеризацию команды и её результат (ошибку или успех). Срабатывает после AuthGate, поэтому в лог попадают только разрешённые фреймы.

---

## 6. Конечный автомат авторизации (команда 0x65)

Обработчик: `internal/cmd/cmd0x65/handler.go` — `Handler`.

### 6.1 Состояния

```
                    ┌──────────────┐
                    │ stepWaitParam │  (0) — ожидание Parameter Request
                    └──────┬───────┘
                           │ Addr=0x61, данные=DID
                           ▼
                    ┌──────────────┐
                    │ stepWaitAuth  │  (1) — ожидание Authorization
                    └──────┬───────┘
                           │ Addr=0x60, данные=DID+version+signature
                           ▼
                    ┌──────────────┐
                    │  stepDone     │  (2) — авторизация завершена
                    └──────────────┘
```

Структура `Handler` хранит состояние:
```go
type Handler struct {
    step      authStep   // текущий шаг
    deviceID  string     // ID устройства (из param-запроса)
    challenge []byte     // сгенерированный challenge
    pubKeyPEM string     // публичный ключ устройства (из БД)
}
```

### 6.2 Шаг 1: Parameter Request

**Фрейм от устройства**: `Addr=0x61, Cmd=0x65, Data=[DID (14 байт)]`

**Гейты (проверки)**:

| # | Проверка                                    | При неудаче                          |
|---|---------------------------------------------|--------------------------------------|
| 1 | `fr.Addr == AddrParamRequest (0x61)`        | Status `0x03` (SpecError), закрытие  |
| 2 | `len(fr.Data) >= DeviceIDSize (14)`         | Status `0x05` (DataLenError), закрытие|
| 3 | Извлечение и trim DID                       | —                                    |
| 4 | `GetPublicKey(DID)` — устройство есть в БД  | Status `0x0A` (CmdExecError), закрытие|
| 5 | `IsInService(DID)` — устройство в эксплуатации| Status `0x0A` (CmdExecError), закрытие|
| 6 | `GenerateChallenge()` — генерация challenge | Status `0x08` (TimeoutError), закрытие|

При успехе:
- Сохраняется `deviceID`, `pubKeyPEM`, `challenge`
- Отправляется фрейм: `Addr=0x64 (ChallengeResponse), Cmd=0x65, Data=[StatusOK(0x00) + challenge(40 байт)]`
- Переход в `stepWaitAuth`

**Challenge** = `nonce (32 случайных байта) + timestamp (8 байт, UnixMilli, little-endian)` = 40 байт.

### 6.3 Шаг 2: Authorization

**Фрейм от устройства**: `Addr=0x60, Cmd=0x65, Data=[DID(14) + Version(1) + Signature(256)]` = 271 байт.

**Гейты (проверки)**:

| # | Проверка                                          | При неудаче                                        |
|---|---------------------------------------------------|----------------------------------------------------|
| 1 | `fr.Addr == AddrAuthCommand (0x60)`              | Status `0x03` (SpecError), закрытие                |
| 2 | `len(fr.Data) >= 271`                            | Status `0x05` (DataLenError), закрытие              |
| 3 | Парсинг DID, version, signature                  | —                                                   |
| 4 | `version == AuthProtocolVersion (0x01)`          | Два статуса: 0x00 + 0x06 (DataValueError), закрытие |
| 5 | `respDID == deviceID` (совпадение с шага 1)      | Два статуса: 0x00 + 0x06, закрытие                  |
| 6 | `!IsChallengeExpired(challenge)` (TTL 5 минут)   | Два статуса: 0x00 + 0x0A (CmdExecError), закрытие   |
| 7 | `VerifyChallengeResponse(pubKey, challenge, sig)`| Два статуса: 0x00 + 0x06 (DataValueError), закрытие |

**RSA-подпись**: RSASSA-PKCS1-V1_5 с SHA-256. Устройство подписывает challenge (nonce+timestamp), полученный на шаге 1.

При успехе:
- Отправляются два статуса: `0x00` (input processed) + `0x01` (authorized)
- `ctx.Authenticated = true`
- `UpdateLastSeen()` — фиксируется момент авторизации (устройство становится отслеживаемым)
- Переход в `stepDone`

> До авторизации `last_seen_at` не обновляется. После неё — обновляется
> в цикле чтения для любого фрейма с корректным CRC (см. раздел 4.2).

### 6.4 Шаблон ответа: два статуса

Ошибки на шаге 2 отправляются особым образом — **два последовательных статус-фрейма**:

```go
func (h *Handler) sendTwoStatuses(conn, ctx, resultCode) {
    h.sendStatus(conn, ctx, StatusOK)      // 0x00 — входное сообщение обработано
    h.sendStatus(conn, ctx, resultCode)    // код результата (0x06 ошибка, 0x01 успех)
}
```

Формат статус-фрейма: `Addr=0x63, Cmd=0x65, Data=[1 байт — код статуса]`.

### 6.5 Диаграмма полного обмена

```
Устройство                              Сервер (CryptoServer + cmd0x65)
    │                                        │
    │── $|0x61|0x65|len=14|DID(14)|CRC ──→   │ 1. Parameter Request
    │                                        │    ├─ Проверка Addr=0x61
    │                                        │    ├─ Проверка длины данных
    │                                        │    ├─ Поиск устройства в БД
    │                                        │    ├─ Проверка in_service
    │                                        │    └─ Генерация challenge (nonce+ts)
    │                                        │
    │←── $|0x64|0x65|len=41|0x00+challenge|CRC ──│ 2. Challenge Response
    │                                        │
    │── $|0x60|0x65|len=271|DID(14)+v(1)+sig(256)|CRC ──→│ 3. Authorization
    │                                        │    ├─ Проверка Addr=0x60
    │                                        │    ├─ Проверка длины
    │                                        │    ├─ Проверка версии протокола
    │                                        │    ├─ Проверка DID match
    │                                        │    ├─ Проверка TTL challenge
    │                                        │    └─ Проверка RSA-подписи
    │                                        │
    │←── $|0x63|0x65|len=1|0x00|CRC ────────│ 4a. Status: input processed
    │←── $|0x63|0x65|len=1|0x01|CRC ────────│ 4b. Status: authorized
    │                                        │
    │  ctx.Authenticated = true              │
    │  Подписка на Hub                       │
    │                                        │
    │── $|0x76|0x59|len=44|data|CRC ──→      │ 5. Регулярные данные (0x59)
    │←── $|0x70|0x59|len=44|data|CRC ──      │    Broadcast через Hub
```

---

## 7. Криптографические операции

Файл: `internal/tcp/crypto.go`

### 7.1 Генерация challenge

```go
func GenerateChallenge() ([]byte, error)
```
- Генерирует 32 случайных байта (`crypto/rand`)
- Добавляет 8-байтовый Unix-timestamp в миллисекундах (little-endian)
- Возвращает 40-байтовый challenge

### 7.2 Проверка срока действия challenge

```go
func ExtractTimestamp(challenge []byte) (time.Time, error)
func IsChallengeExpired(challenge []byte) (bool, error)
```
- Извлекает timestamp из последних 8 байт
- Сравнивает `time.Since(ts) > ChallengeTTL` (5 минут)

### 7.3 Парсинг ключей

```go
func ParsePublicKey(pemStr string) (*rsa.PublicKey, error)
func ParsePrivateKey(pemStr string) (*rsa.PrivateKey, error)
```
- Декодирует PEM-блок
- Для публичного: пробует PKIX (`x509.ParsePKIXPublicKey`), затем PKCS1 (`x509.ParsePKCS1PublicKey`)
- Для приватного: пробует PKCS8, затем PKCS1

### 7.4 Подпись и проверка

```go
func SignChallenge(priv *rsa.PrivateKey, challenge []byte) ([]byte, error)
func VerifyChallengeResponse(pub *rsa.PublicKey, challenge, signature []byte) error
```
- Алгоритм: **RSASSA-PKCS1-V1_5** с **SHA-256**
- `SignChallenge` — используется на стороне устройства (клиент)
- `VerifyChallengeResponse` — используется сервером для проверки подписи устройства над challenge

---

## 8. Взаимодействие с базой данных (DeviceStore)

Файл: `internal/store/device_store.go`

### Методы, используемые при авторизации

| Метод           | SQL                                                                 | Назначение                                   |
|-----------------|---------------------------------------------------------------------|----------------------------------------------|
| `GetPublicKey`  | `SELECT public_key FROM devices WHERE id=$1 AND deleted_at IS NULL AND public_key IS NOT NULL` | Получение RSA-публичного ключа устройства    |
| `IsInService`   | `SELECT in_service FROM devices WHERE id=$1 AND deleted_at IS NULL` | Проверка, что устройство в эксплуатации      |
| `UpdateLastSeen`| `UPDATE devices SET last_seen_at = NOW() WHERE id=$1 AND deleted_at IS NULL` | Обновление времени последней активности      |

### Схема таблицы `devices`

```sql
CREATE TABLE devices (
    id            TEXT PRIMARY KEY,          -- Device ID (до 10 символов)
    password_hash TEXT NOT NULL DEFAULT '',  -- хеш пароля (bcrypt)
    public_key    TEXT,                      -- RSA публичный ключ (PEM)
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ,              -- soft delete
    in_service    BOOLEAN NOT NULL DEFAULT false,  -- статус эксплуатации
    updated_by    UUID,                     -- FK → users
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ              -- время последней активности
);
```

### Требования к устройству для авторизации

1. Запись существует в таблице `devices`
2. `deleted_at IS NULL` (устройство не удалено)
3. `public_key IS NOT NULL` (ключ зарегистрирован)
4. `in_service = true` (устройство в эксплуатации)

При невыполнении любого условия — соединение закрывается со статусом ошибки.

---

## 9. Hub: pub/sub после авторизации

Файл: `internal/hub/hub.go`

После успешной авторизации (`ctx.Authenticated = true`) сервер подписывает соединение на Hub:

```go
sub = s.hub.Subscribe()                    // создать подписчика
go func() {                                // горутина рассылки входящих broadcast-сообщений
    for data := range sub.C {              // читаем из канала подписчика
        // data = [Addr(1)|Cmd(1)|Payload(N)]
        conn.Write(EncodeFrame(...))       // отправляем устройству
    }
}()
```

Hub работает по модели pub/sub:
- **Подписка**: `Subscribe()` → возвращает `*Subscriber` с буферизованным каналом (64 сообщения)
- **Отправка**: `Broadcast(data, senderID)` → рассылает всем подписчикам, КРОМЕ отправителя
- **Отписка**: `Unsubscribe(sub)` — при закрытии соединения
- **Overflow**: если канал подписчика переполнен — сообщение отбрасывается (медленный потребитель)

Hub используется обработчиком `cmd0x59` для broadcast регулярных сообщений, а также для любых других команд, возвращающих `DeliverBroadcast`.

---

## 10. Регистрация обработчиков команд (Registry)

Файлы: `internal/cmd/registry.go`, `internal/cmd/doc.go`

### Механизм регистрации

```
cmd0x59/init() ──→ cmd.Register(0x59, factory)
cmd0x65/init() ──→ cmd.Register(0x65, factory)
                        │
                        ▼
                  registry map[byte]HandlerFactory
                        │
                        ▼
            main.go: cmd.GetAll() → передаётся в NewCryptoServer()
```

Каждый пакет-обработчик в `internal/cmd/cmd0xNN/`:
1. Реализует `tcp.CmdHandler`
2. В `init()` вызывает `cmd.Register(cmdByte, factory)`
3. Регистрируется пустым импортом (`_ "..."`) в `main.go`

**Важно**: `HandlerFactory` создаёт **новый экземпляр** обработчика для каждого соединения. Это критично для stateful-обработчиков (как `cmd0x65`), чтобы избежать гонок между соединениями.

---

## 11. Код: все классы и функции

### 11.1 `internal/tcp/frame.go` — Бинарный фрейм

```go
// Frame — распарсенный бинарный фрейм.
type Frame struct {
    Addr byte
    Cmd  byte
    Data []byte
}

// Константы протокола
const (
    FramePreamble   = '$'
    FrameMinLen     = 6
    FrameMaxDataLen = 1024
    FrameMaxLen     = FrameMinLen + FrameMaxDataLen

    AddrAuthCommand       = 0x60
    AddrParamRequest      = 0x61
    AddrServerStatus      = 0x63
    AddrChallengeResponse = 0x64
    AddrDeviceRegular     = 0x76
    AddrBroadcast         = 0x70

    CmdAuth    byte = 0x65
    CmdRegular byte = 0x59

    StatusOK             byte = 0x00
    StatusAuthorized     byte = 0x01
    StatusAddrError      byte = 0x02
    StatusSpecError      byte = 0x03
    StatusNumberError    byte = 0x04
    StatusDataLenError   byte = 0x05
    StatusDataValueError byte = 0x06
    StatusIntegrityError byte = 0x07
    StatusTimeoutError   byte = 0x08
    StatusSeqError       byte = 0x09
    StatusCmdExecError   byte = 0x0A

    DeviceIDSize         = 14
    AuthProtocolVersion  byte = 0x01
)

func EncodeFrame(f Frame) []byte
func DecodeFrame(raw []byte) (Frame, error)
func crcCalc(buf []byte) byte
```

### 11.2 `internal/tcp/crypto_server.go` — Сервер и чтение фреймов

```go
// CryptoServer — TCP-сервер, принимает соединения и диспетчеризует фреймы.
type CryptoServer struct {
    addr     string
    devices  *store.DeviceStore
    hub      *hub.Hub
    logChan  chan<- string
    handlers map[byte]HandlerFactory
    ln       net.Listener
    wg       sync.WaitGroup
    quit     chan struct{}
}

func NewCryptoServer(addr string, devices *store.DeviceStore, h *hub.Hub,
    logChan chan<- string, handlers map[byte]HandlerFactory) *CryptoServer

func (s *CryptoServer) ListenAndServe() error
func (s *CryptoServer) Shutdown()
func (s *CryptoServer) handleConnection(conn net.Conn)        // ← основной цикл
func (s *CryptoServer) logRawFrame(deviceID string, raw []byte)
func (s *CryptoServer) logEvent(eventType, deviceID, message string)

// Вспомогательные
func padDeviceID(id string) []byte
func TrimDeviceID(b []byte) string

// FrameReader — читает фреймы из bufio.Reader с поиском preamble.
type FrameReader struct { rd *bufio.Reader }
func NewFrameReader(rd *bufio.Reader) *FrameReader
func (fr *FrameReader) ReadFrame() (Frame, []byte, error)

// FormatLog — создаёт JSON-строку для web-логов.
func FormatLog(eventType, deviceID, message string) string
```

### 11.3 `internal/tcp/handler.go` — Контекст и интерфейс обработчика

```go
// CmdContext — per-connection контекст, разделяемый между обработчиками.
type CmdContext struct {
    Devices       *store.DeviceStore
    Hub           *hub.Hub
    LogChan       chan<- string
    DeviceID      string
    Authenticated bool
}

// CmdHandler — интерфейс обработчика одной команды.
type CmdHandler interface {
    Handle(fr Frame, conn net.Conn, ctx *CmdContext) (*Message, error)
}

// HandlerFactory — фабрика: создаёт новый CmdHandler для каждого соединения.
type HandlerFactory func() CmdHandler
```

### 11.4 `internal/tcp/message.go` — Типизированное сообщение

```go
type DeliveryMode int

const (
    DeliverNone      DeliveryMode = iota // ответ уже отправлен
    DeliverBroadcast                     // broadcast через Hub
    DeliverUnicast                       // ответ только отправителю
    DeliverDirect                        // маршрутизация конкретным устройствам
)

func (m DeliveryMode) String() string

// Message — типизированный контракт между обработчиком и CryptoServer.
type Message struct {
    Mode    DeliveryMode
    Addr    byte
    Cmd     byte
    Payload []byte
    Targets []string
}

func (m *Message) WireBytes() []byte // → [Addr|Cmd|Payload]
```

### 11.5 `internal/tcp/middleware.go` — Middleware-пайплайн

```go
// Middleware — обёртка над CmdHandler.
type Middleware func(next CmdHandler) CmdHandler

// Pipeline — цепочка middleware: mw1(mw2(mw3(handler))).
func Pipeline(handler CmdHandler, mws ...Middleware) CmdHandler

// AuthGate — middleware, блокирующий все команды кроме 0x65 до аутентификации.
func AuthGate() Middleware

// Logging — middleware, логирующий диспетчеризацию и результат.
func Logging() Middleware
```

### 11.6 `internal/tcp/crypto.go` — Криптография

```go
const (
    ChallengeSize = 32
    TimestampSize = 8
    ChallengeTTL  = 5 * time.Minute
)

func GenerateChallenge() ([]byte, error)
func ExtractTimestamp(challenge []byte) (time.Time, error)
func IsChallengeExpired(challenge []byte) (bool, error)
func ParsePublicKey(pemStr string) (*rsa.PublicKey, error)
func ParsePrivateKey(pemStr string) (*rsa.PrivateKey, error)
func SignChallenge(priv *rsa.PrivateKey, challenge []byte) ([]byte, error)
func VerifyChallengeResponse(pub *rsa.PublicKey, challenge, signature []byte) error
```

### 11.7 `internal/cmd/cmd0x65/handler.go` — Конечный автомат авторизации

```go
package cmd0x65

func init()  // auto-register: cmd.Register(tcp.CmdAuth, factory)

type authStep int
const (
    stepWaitParam authStep = iota  // 0
    stepWaitAuth                    // 1
    stepDone                        // 2
)

type Handler struct {
    step      authStep
    deviceID  string
    challenge []byte
    pubKeyPEM string
}

func (h *Handler) Handle(fr tcp.Frame, conn net.Conn, ctx *tcp.CmdContext) (*tcp.Message, error)
func (h *Handler) handleParamRequest(fr tcp.Frame, conn net.Conn, ctx *tcp.CmdContext) (*tcp.Message, error)
func (h *Handler) handleAuth(fr tcp.Frame, conn net.Conn, ctx *tcp.CmdContext) (*tcp.Message, error)
func (h *Handler) sendTwoStatuses(conn net.Conn, ctx *tcp.CmdContext, resultCode byte)
func (h *Handler) sendStatus(conn net.Conn, ctx *tcp.CmdContext, code byte)
func (h *Handler) IsDone() bool

func logDebug(ctx *tcp.CmdContext, format string, args ...interface{})
func logEvent(ctx *tcp.CmdContext, eventType, message string)
```

### 11.8 `internal/cmd/registry.go` — Реестр команд

```go
package cmd

func Register(cmd byte, factory tcp.HandlerFactory)  // паникует при дубликате
func GetAll() map[byte]tcp.HandlerFactory
func Has(cmd byte) bool
```

### 11.9 `internal/store/device_store.go` — Хранилище устройств

```go
type DeviceStore struct { pool *pgxpool.Pool }

func NewDeviceStore(pool *pgxpool.Pool) *DeviceStore

// Методы, используемые при TCP-авторизации:
func (s *DeviceStore) GetPublicKey(ctx context.Context, deviceID string) (string, error)
func (s *DeviceStore) IsInService(ctx context.Context, deviceID string) (bool, error)
func (s *DeviceStore) UpdateLastSeen(ctx context.Context, deviceID string) error
```

### 11.10 `internal/hub/hub.go` — Pub/Sub хаб

```go
type Hub struct { ... }
func New() *Hub
func (h *Hub) Run()
func (h *Hub) Subscribe() *Subscriber
func (h *Hub) Unsubscribe(s *Subscriber)
func (h *Hub) Broadcast(data []byte, senderID uint64)
func (h *Hub) MsgTotal() uint64
func (h *Hub) SubCount() int64
func (h *Hub) Stop()

type Subscriber struct { C chan []byte; id uint64 }
func (s *Subscriber) ID() uint64
```

### 11.11 `internal/models/models.go` — Модели данных

```go
type Device struct {
    ID           string
    PublicKey    string
    RegisteredAt time.Time
    DeletedAt    *time.Time
    InService    bool
    UpdatedBy    *uuid.UUID
    UpdatedAt    time.Time
    LastSeenAt   *time.Time
    IsOnline     bool
}
```

---

## Краткий итог

Авторизация TCP-соединения в TNC-server — трёхшаговый challenge-response протокол на базе RSA-подписи:

1. **Parameter Request** — устройство отправляет свой DID; сервер проверяет наличие в БД и статус `in_service`.
2. **Challenge** — сервер генерирует nonce+timestamp и отправляет устройству.
3. **Authorization** — устройство подписывает challenge своим RSA-ключом (RSASSA-PKCS1-V1_5 + SHA-256) и отправляет серверу. Сервер проверяет подпись публичным ключом из БД.

После успешной проверки контекст помечается как `Authenticated`, соединение подписывается на Hub для приёма broadcast-сообщений, и устройство может отправлять команду `0x59` (регулярные данные).
