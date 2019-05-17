package webca

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"sync"
	"time"
)

const (
	SESSIONID     = "goSessionId"
	LASTUSED      = "goLastUsed"
	CLEANUPDELAY  = time.Minute
	MAXSESSIONAGE = 30 * time.Minute
)

// session type
type session map[string]interface{}

// sessions holds all sessions
var sessions map[string]session

// mutex lock for session access
var smutex sync.RWMutex

func ReapSessions() {
	go func() {
		for {
			time.Sleep(CLEANUPDELAY)
			cleanupSessions()
		}
	}()
}

func cleanupSessions() {
	smutex.RLock()
	defer smutex.RUnlock()

	for k, s := range sessions {
		if s.expired() {
			log.Printf("Session %s has expired, removing...", k)
			delete(sessions, k)
		}
	}
}

// requestSessionId retrieves the session cookie from the request or creates a new one
func requestSessionId(w http.ResponseWriter, r *http.Request) (string, error) {
	cookie, e := r.Cookie(SESSIONID)
	if e != nil && e != http.ErrNoCookie {
		return "", e
	}
	if e == http.ErrNoCookie || cookie == nil {
		id, e := genId()
		if e != nil {
			return "", e
		}
		cookie = &http.Cookie{Name: SESSIONID, Value: id, Path: "/", MaxAge: 0}
		http.SetCookie(w, cookie)
		r.AddCookie(cookie) // for future references of this request
	}
	return cookie.Value, nil
}

// SessionFor gets a session bound to a Request by Session ID
func SessionFor(w http.ResponseWriter, r *http.Request) (session, error) {
	id, e := requestSessionId(w, r)
	if e != nil {
		return nil, e
	}
	smutex.RLock()
	defer smutex.RUnlock()
	if sessions == nil {
		sessions = make(map[string]session)
	}
	s := sessions[id]
	if s == nil {
		s = make(session)
		s[SESSIONID] = id
		sessions[id] = s
	}
	s[LASTUSED] = time.Now()
	return s.clone(), nil // this copy allows concurrent session access
}

// RemoveSession deletes a session from the map and removes the cookie
func RemoveSession(w http.ResponseWriter, r *http.Request) {
	cookie, e := r.Cookie(SESSIONID)
	if e != nil {
		return
	}
	smutex.RLock()
	defer smutex.RUnlock()
	delete(sessions, cookie.Value)
	cookie.MaxAge = 0
	http.SetCookie(w, cookie)
}

// Id returns the session ID or ""
func (s session) Id() string {
	if s[SESSIONID] != nil {
		return s[SESSIONID].(string)
	}
	return ""
}

// Save stores the session state
func (s session) Save() {
	smutex.Lock()
	defer smutex.Unlock()
	sessions[s.Id()] = s.clone()
}

// clone makes a copy of a session and returns it
func (s session) clone() session {
	c := make(session, len(s))
	for k, v := range s {
		c[k] = v
	}
	return c
}

func (s session) expired() bool {
	now := time.Now()
	return now.Sub(s[LASTUSED].(time.Time)) >= MAXSESSIONAGE
}

// genId generates a new session ID
func genId() (string, error) {
	uuid := make([]byte, 16)
	n, err := rand.Read(uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	// TODO: verify the two lines implement RFC 4122 correctly
	uuid[8] = 0x80 // variant bits see page 5
	uuid[4] = 0x40 // version 4 Pseudo Random, see page 7
	return hex.EncodeToString(uuid), nil
}
