package walletconnectgo

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type keyManager struct {
	sync.Mutex
	relayerAuthKey ed25519.PrivateKey
	walletPrivKey  *ecdh.PrivateKey
	topicKeys      map[string][]byte
}

func (km *keyManager) Get(topic string) ([]byte, bool) {
	val, ok := km.topicKeys[topic]
	return val, ok
}

func (km *keyManager) initTopicKeys() {
	km.Lock()
	defer km.Unlock()
	km.topicKeys = make(map[string][]byte)
}

func (km *keyManager) Set(key []byte) string {
	if km.topicKeys == nil {
		km.initTopicKeys()
	}

	hash := sha256.Sum256(key)
	topic := hex.EncodeToString(hash[:])

	km.Lock()
	defer km.Unlock()
	km.topicKeys[topic] = key

	return topic
}

func (km *keyManager) initRelayerAuthKey() error {
	km.Lock()
	defer km.Unlock()

	_, pri, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	km.relayerAuthKey = pri
	return nil
}

func (km *keyManager) GetRelayerJwtAuth(relayer string) (string, error) {
	if km.relayerAuthKey == nil {
		if err := km.initRelayerAuthKey(); err != nil {
			return "", err
		}
	}

	pub := km.relayerAuthKey.Public().(ed25519.PublicKey)
	base58Pub := base58.Encode(append([]byte{0xED, 0x01}, pub...))

	didKey := strings.Join([]string{"did", "key", "z" + base58Pub}, ":")

	now := time.Now()
	randomHash := sha256.Sum256([]byte(strconv.FormatInt(now.UnixNano(), 10)))

	tk := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": didKey,
		"sub": hex.EncodeToString(randomHash[:]),
		"aud": relayer,
		"iat": now.Unix(),
		"exp": now.Add(JWTTimeout).Unix(),
		"act": "client_auth",
	})
	signedJwt, err := tk.SignedString(km.relayerAuthKey)
	if err != nil {
		return "", err
	}
	return signedJwt, nil
}

func (km *keyManager) initWalletPrivKey() error {
	km.Lock()
	defer km.Unlock()

	pri, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	km.walletPrivKey = pri
	return nil
}

func (km *keyManager) GetWalletPublicKey() (*ecdh.PublicKey, error) {
	if km.walletPrivKey == nil {
		if err := km.initWalletPrivKey(); err != nil {
			return nil, err
		}
	}

	return km.walletPrivKey.PublicKey(), nil
}

func (km *keyManager) DeriveSharedKey(pub *ecdh.PublicKey) ([]byte, error) {
	if km.walletPrivKey == nil {
		if err := km.initWalletPrivKey(); err != nil {
			return nil, err
		}
	}

	ecdhKey, err := km.walletPrivKey.ECDH(pub)
	if err != nil {
		return nil, err
	}

	hkdfReader := hkdf.New(sha256.New, ecdhKey, nil, nil)

	derived := make([]byte, 32)
	if _, err := hkdfReader.Read(derived); err != nil {
		return nil, err
	}

	return derived, nil
}

func chacha20poly1305Encrypt(plaintext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	rand.Read(nonce)
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func chacha20poly1305Decrypt(ciphertext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce, cipherText := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, cipherText, nil)
}
