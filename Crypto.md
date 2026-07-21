Логика работы (без timestamp в подписи)
Сервер при новом TCP‑соединении:

Генерирует криптографически стойкий random challenge_nonce (32 байта).
Сохраняет его во временное хранилище с пометкой «ожидает ответа» и TTL, например, 5 минут.
Отправляет клиенту.
Устройство:

Получает challenge_nonce.
Формирует data_to_sign = DeviceID || challenge_nonce.
Подписывает приватным ключом (Ed25519).
Отправляет DeviceID, Signature, challenge_nonce.
Сервер:

По DeviceID достаёт публичный ключ.
Проверяет, что challenge_nonce есть в хранилище и помечен как «ожидает».
Проверяет подпись.
Если всё ок:
Помечает nonce как «использован» (чтобы нельзя было повторить).
Генерирует session_token (random 32 байта) и его срок жизни.
Отправляет токен клиенту.
Если nonce не найден, истёк по TTL или уже использован — разрыв соединения.
Дальше все сообщения идут с session_token. Сервер проверяет его валидность и срок жизни. При разрыве TCP устройство просто подключается заново и сразу шлёт данные с токеном (если он ещё не истёк).


#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// device_id — фиксированный ID устройства (например, 8 байт)
// challenge_nonce — 32 байта, получены от сервера
// priv_key_pem — приватный ключ Ed25519 (PEM или raw)

int sign_auth_response(const uint8_t *device_id, size_t device_id_len,
                       const uint8_t *challenge_nonce, uint8_t *out_signature) {

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    // Парсим приватный ключ (пример для PEM)
    int ret = mbedtls_pk_parse_key(&pk, priv_key_pem, strlen((char*)priv_key_pem), NULL, 0);
    if (ret != 0) return -1;

    // Данные для подписи: DeviceID || Nonce
    uint8_t data_to_sign[256];
    size_t data_len = 0;
    memcpy(data_to_sign, device_id, device_id_len); data_len += device_id_len;
    memcpy(data_to_sign + data_len, challenge_nonce, 32); data_len += 32;

    // Ed25519 не требует хеш на входе, mbedTLS сам сделает SHA‑512
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char *pers = "stm32_auth";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) { mbedtls_pk_free(&pk); return -2; }

    size_t olen;
    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA512, data_to_sign, data_len,
                          out_signature, &olen, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return (ret == 0 && olen == 64) ? 0 : -3;
}




Реализация проверки на Go (tnc‑server)

package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	NonceTTL = 5 * time.Minute
	MaxNoncesPerDevice = 1000
)

type challenge struct {
	nonce     []byte
	expiresAt time.Time
	used      bool
}

type deviceState struct {
	mu      sync.RWMutex
	challenges map[string]*challenge // nonceHex -> challenge
	tokens     map[string]sessionToken // tokenHex -> token
}

type sessionToken struct {
	expiry time.Time
}

var deviceStates = make(map[string]*deviceState)
var statesMu sync.RWMutex

func getDeviceState(id string) *deviceState {
	statesMu.Lock()
	defer statesMu.Unlock()
	s, ok := deviceStates[id]
	if !ok {
		s = &deviceState{
			challenges: make(map[string]*challenge),
			tokens:     make(map[string]sessionToken),
		}
		deviceStates[id] = s
	}
	return s
}

func generateChallenge(devID string) ([]byte, error) {
	state := getDeviceState(devID)
	state.mu.Lock()
	defer state.mu.Unlock()

	nonce := make([]byte, 32)
	if _, err := readRandom(nonce); err != nil { // реализуй через crypto/rand
		return nil, err
	}

	// очистка истёкших
	now := time.Now()
	for k, c := range state.challenges {
		if c.expiresAt.Before(now) {
			delete(state.challenges, k)
		}
	}

	if len(state.challenges) > MaxNoncesPerDevice {
		// простая очистка: удаляем половину
		i := 0
		for k := range state.challenges {
			delete(state.challenges, k)
			i++
			if i > MaxNoncesPerDevice/2 {
				break
			}
		}
	}

	hexNonce := fmt.Sprintf("%x", nonce)
	state.challenges[hexNonce] = &challenge{
		nonce:     nonce,
		expiresAt: now.Add(NonceTTL),
		used:      false,
	}
	return nonce, nil
}

func verifyAuth(devID, hexNonce, hexSig, hexPubKey string) error {
	pubKeyBytes, err := hexDecode(hexPubKey) // реализуй hex decode
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}
	pub := ed25519.PublicKey(pubKeyBytes)

	sigBytes, err := hexDecode(hexSig)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return errors.New("invalid signature")
	}

	nonceBytes, err := hexDecode(hexNonce)
	if err != nil || len(nonceBytes) != 32 {
		return errors.New("invalid nonce")
	}

	state := getDeviceState(devID)
	state.mu.Lock()
	defer state.mu.Unlock()

	c, ok := state.challenges[hexNonce]
	if !ok {
		return errors.New("nonce not found or expired")
	}
	if c.used {
		return errors.New("nonce already used (replay)")
	}
	if c.expiresAt.Before(time.Now()) {
		delete(state.challenges, hexNonce)
		return errors.New("nonce expired")
	}

	dataToSign := append([]byte(devID), nonceBytes...)
	if !ed25519.Verify(pub, dataToSign, sigBytes) {
		return errors.New("signature verification failed")
	}

	c.used = true // помечаем как использованный
	return nil
}

// далее: генерация sessionToken, проверка токена в обычных сообщениях
