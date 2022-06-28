package oidc

//
//import (
//	"crypto/aes"
//	"crypto/cipher"
//	"crypto/tls"
//	"crypto/x509"
//	"encoding/base64"
//	"encoding/json"
//	"errors"
//	"fmt"
//	"net/http"
//	"path"
//	"time"
//
//	"github.com/google/uuid"
//	"github.com/kvtools/valkeyrie"
//	"github.com/kvtools/valkeyrie/store"
//	"github.com/kvtools/valkeyrie/store/consul"
//	etcdv3 "github.com/kvtools/valkeyrie/store/etcd/v3"
//	"github.com/kvtools/valkeyrie/store/redis"
//	"github.com/kvtools/valkeyrie/store/zookeeper"
//	"github.com/traefik/traefikee/v2/pkg/config/static"
//	traefikeetls "github.com/traefik/traefikee/v2/pkg/config/tls"
//)
//
//// KVSessionStore stores and retrieves session in a KV store.
//type KVSessionStore struct {
//	name string
//	cfg *AuthSession
//
//	keyPrefix string
//
//	store store.Store
//
//	block cipher.Block
//	rand  Randr
//}
//
//// NewKVSessionStore creates a KV session store.
//func NewKVSessionStore(source string, cfg *AuthSession, storageCfg *static.Store, middlewarePrefix string, rand Randr) (*KVSessionStore, error) {
//	block, err := aes.NewCipher([]byte(cfg.Secret))
//	if err != nil {
//		return nil, err
//	}
//
//	backend, storeCfg, err := buildConfig(storageCfg)
//	if err != nil {
//		return nil, err
//	}
//
//	// N.B: If there was no file: allowEmpty on the fields of static.Store,
//	// and in the case where none of the fields of the underlying static.KV were set
//	// (because the user did not set any of them in the config), then paerser would
//	// explode with an obscure message when applying the conf. And we would never get to here,
//	// where we can actually log a useful error for the user.
//	// That is why allowEmpty is necessary in static.Store.
//	if len(storeCfg.Endpoints) == 0 {
//		return nil, fmt.Errorf("endpoints not specified in configuration for %v KV store", backend)
//	}
//
//	s, err := createStore(backend, storeCfg)
//	if err != nil {
//		return nil, fmt.Errorf("creating store: %w", err)
//	}
//
//	return &KVSessionStore{
//		name:       source,
//		cfg:       cfg,
//		keyPrefix: path.Join(storeCfg.KeyPrefix, middlewarePrefix),
//		store:     s,
//		block:     block,
//		rand:      rand,
//	}, nil
//}
//
//// Create stores the session data into the KV store,
//// and creates a cookie containing the corresponding session ID.
//func (s *KVSessionStore) Create(w http.ResponseWriter, data SessionData) error {
//	return s.putSession(w, []byte(uuid.NewString()), data)
//}
//
//// Update updates the KV store with session data corresponding to the session ID found in the cookie.
//// It also updates the cookie.
//// If no session ID is found it calls Create.
//func (s *KVSessionStore) Update(w http.ResponseWriter, r *http.Request, data SessionData) error {
//	name := resolveCookieName(s.cfg.Name, s.name)
//
//	sessID, ok := getCookie(r, name)
//	if !ok {
//		return s.Create(w, data)
//	}
//
//	return s.putSession(w, sessID, data)
//}
//
//func (s *KVSessionStore) putSession(w http.ResponseWriter, sessID []byte, data SessionData) error {
//	sessData, err := s.encode(data)
//	if err != nil {
//		return fmt.Errorf("encode session data: %w", err)
//	}
//
//	opts := &store.WriteOptions{
//		TTL: time.Duration(*s.cfg.Expiry) * time.Second,
//	}
//	// TODO: with consul, the TTL associated with the key is not updated.
//	if err = s.store.Put(s.sessionKey(sessID), sessData, opts); err != nil {
//		return fmt.Errorf("store session data: %w", err)
//	}
//
//	http.SetCookie(w, &http.Cookie{
//		Name:     resolveCookieName(s.cfg.Name, s.name),
//		Value:    string(sessID),
//		Path:     s.cfg.Path,
//		Domain:   s.cfg.Domain,
//		MaxAge:   *s.cfg.Expiry,
//		HttpOnly: *s.cfg.HTTPOnly,
//		SameSite: parseSameSite(s.cfg.SameSite),
//		Secure:   s.cfg.Secure,
//	})
//
//	return nil
//}
//
//// Delete expires the session ID cookie on the HTTP response,
//// and removes the corresponding session data in the KV store.
//func (s *KVSessionStore) Delete(w http.ResponseWriter, r *http.Request) error {
//	name := resolveCookieName(s.cfg.Name, s.name)
//
//	sessID, ok := getCookie(r, name)
//	if !ok {
//		return nil
//	}
//
//	err := s.store.Delete(s.sessionKey(sessID))
//	if err != nil && !errors.Is(err, store.ErrKeyNotFound) {
//		return fmt.Errorf("delete sesssion data: %w", err)
//	}
//
//	http.SetCookie(w, &http.Cookie{
//		Name:   name,
//		Path:   s.cfg.Path,
//		Domain: s.cfg.Domain,
//		MaxAge: -1, // Invalidates the cookie.
//	})
//
//	return nil
//}
//
//// Get retrieves in the KV store the session data corresponding to the session ID found in the cookie.
//func (s *KVSessionStore) Get(r *http.Request) (*SessionData, error) {
//	name := resolveCookieName(s.cfg.Name, s.name)
//
//	sessID, ok := getCookie(r, name)
//	if !ok {
//		return nil, nil
//	}
//
//	sessData, err := s.store.Get(s.sessionKey(sessID), nil)
//	if errors.Is(err, store.ErrKeyNotFound) {
//		return nil, nil
//	}
//	if err != nil {
//		return nil, fmt.Errorf("get session data: %w", err)
//	}
//
//	sess, err := s.decode(sessData.Value)
//	if err != nil {
//		return nil, fmt.Errorf("decode session data: %w", err)
//	}
//	return &sess, nil
//}
//
//// RemoveCookie removes the session ID cookie from the request.
//func (s *KVSessionStore) RemoveCookie(r *http.Request) {
//	deleteCookie(r, fmt.Sprintf(s.cfg.Name, s.name))
//}
//
//func (s *KVSessionStore) encode(session SessionData) ([]byte, error) {
//	blockSize := s.block.BlockSize()
//
//	ser, err := json.Marshal(session)
//	if err != nil {
//		return nil, fmt.Errorf("unable to serialize session: %w", err)
//	}
//
//	encrypted := make([]byte, blockSize+len(ser))
//	iv := s.rand.Bytes(blockSize)
//	copy(encrypted[:blockSize], iv)
//	stream := cipher.NewCTR(s.block, iv)
//	stream.XORKeyStream(encrypted[blockSize:], ser)
//
//	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(encrypted)))
//	base64.RawURLEncoding.Encode(encoded, encrypted)
//
//	return encoded, nil
//}
//
//func (s *KVSessionStore) decode(p []byte) (SessionData, error) {
//	blockSize := s.block.BlockSize()
//
//	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(p)))
//	if _, err := base64.RawURLEncoding.Decode(decoded, p); err != nil {
//		return SessionData{}, fmt.Errorf("unable to decode session: %w", err)
//	}
//
//	decrypted := make([]byte, len(decoded)-blockSize)
//	iv := decoded[:blockSize]
//	stream := cipher.NewCTR(s.block, iv)
//	stream.XORKeyStream(decrypted, decoded[blockSize:])
//
//	var sess SessionData
//	if err := json.Unmarshal(decrypted, &sess); err != nil {
//		return SessionData{}, fmt.Errorf("unable to deserialize session: %w", err)
//	}
//	return sess, nil
//}
//
//func (s *KVSessionStore) sessionKey(sessID []byte) string {
//	return path.Join(s.keyPrefix, string(sessID))
//}
//
//func createStore(backend store.Backend, cfg *static.KV) (store.Store, error) {
//	options := &store.Config{
//		ConnectionTimeout: 3 * time.Second,
//		Username:          cfg.Username,
//		Password:          cfg.Password,
//		Token:             cfg.Token,
//		Namespace:         cfg.Namespace,
//	}
//
//	if cfg.TLS != nil {
//		var err error
//		options.TLS, err = buildTLSConfig(cfg.TLS)
//		if err != nil {
//			return nil, fmt.Errorf("build TLS config: %w", err)
//		}
//	}
//
//	switch backend {
//	case store.CONSUL:
//		consul.Register()
//
//	case store.ETCDV3:
//		etcdv3.Register()
//
//	case store.ZK:
//		zookeeper.Register()
//
//	case store.REDIS:
//		redis.Register()
//	}
//
//	return valkeyrie.NewStore(backend, cfg.Endpoints, options)
//}
//
//func buildConfig(storage *static.Store) (store.Backend, *static.KV, error) {
//	if storage.Consul != nil {
//		return store.CONSUL, storage.Consul, nil
//	}
//
//	if storage.Etcd != nil {
//		return store.ETCDV3, storage.Etcd, nil
//	}
//
//	if storage.Zookeeper != nil {
//		return store.ZK, storage.Zookeeper, nil
//	}
//
//	if storage.Redis != nil {
//		return store.REDIS, storage.Redis, nil
//	}
//
//	return "", nil, errors.New("unknown storage backend")
//}
//
//func buildTLSConfig(cfg *traefikeetls.TLS) (*tls.Config, error) {
//	pool, err := x509.SystemCertPool()
//	if err != nil {
//		pool = x509.NewCertPool()
//	}
//
//	if cfg.CABundle != "" {
//		var content []byte
//		content, err = cfg.CABundle.Read()
//		if err != nil {
//			return nil, fmt.Errorf("read CA bundle content: %w", err)
//		}
//
//		if !pool.AppendCertsFromPEM(content) {
//			return nil, errors.New("wrong CA bundle")
//		}
//	}
//
//	return &tls.Config{
//		RootCAs:            pool,
//		InsecureSkipVerify: cfg.InsecureSkipVerify,
//	}, nil
//}
