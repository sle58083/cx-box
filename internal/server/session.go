package server

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// sessionStore 是内存会话存储（单机面板足够；进程重启后需重新登录）。
type sessionStore struct {
	mu   sync.Mutex
	data map[string]sessionEntry
}

type sessionEntry struct {
	username string
	expires  time.Time
}

const sessionTTL = 7 * 24 * time.Hour

func newSessionStore() *sessionStore {
	return &sessionStore{data: map[string]sessionEntry{}}
}

// Create 新建会话，返回随机 token。
func (s *sessionStore) Create(username string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[token] = sessionEntry{username: username, expires: time.Now().Add(sessionTTL)}
	return token
}

// Valid 校验 token 是否有效（顺带清理过期项）。
func (s *sessionStore) Valid(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[token]
	if !ok {
		return false
	}
	if time.Now().After(e.expires) {
		delete(s.data, token)
		return false
	}
	return true
}

// Delete 注销会话。
func (s *sessionStore) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, token)
}
