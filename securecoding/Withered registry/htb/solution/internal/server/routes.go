package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"git.witheredregistry.realm/registry/internal/store"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) authenticate(username, password string) (*store.Scribe, error) {
	c, err := s.store.ScribeByUsername(username)
	if err != nil {
		return nil, errors.New("unknown scribe or wrong pass-phrase")
	}
	if bcrypt.CompareHashAndPassword([]byte(c.PassHash()), []byte(password)) != nil {
		return nil, errors.New("unknown scribe or wrong pass-phrase")
	}
	return c, nil
}

func (s *Server) handleAPILogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	c, err := s.authenticate(req.Username, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	token, err := s.issueSession(c)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not mint session"})
		return
	}
	s.setSessionCookie(w, token)
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"scribe": map[string]any{
			"username":     c.Username,
			"display_name": c.DisplayName,
			"house_id":     c.HouseID,
		},
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"username": p.Username,
		"house_id": p.HouseID,
	})
}

func (s *Server) handleHouses(w http.ResponseWriter, r *http.Request) {
	houses, err := s.store.Houses()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ledger unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"houses": houses})
}

func (s *Server) handleDecrees(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)

	if asked := strings.TrimSpace(r.URL.Query().Get("house_id")); asked != "" && !ownsHouse(p, asked) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "a scribe may only read the decrees of the house they serve",
		})
		return
	}

	house := houseOf(p)
	decrees, err := s.store.DecreesForHouse(house)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ledger unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"house":   house,
		"decrees": decrees,
	})
}

func (s *Server) handleDecree(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad decree id"})
		return
	}
	decree, err := s.store.Decree(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such decree"})
		return
	}
	if !ownsHouse(p, decree.HouseID) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "a scribe may only read the decrees of the house they serve",
		})
		return
	}
	writeJSON(w, http.StatusOK, decree)
}

func (s *Server) handleWrits(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r)
	writs, err := s.store.WritsForHouse(houseOf(p))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ledger unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"house": houseOf(p),
		"writs": writs,
	})
}

type recogniseRequest struct {
	HouseID string `json:"house_id"`
}

// Query parameters take precedence over the JSON body for compatibility.
func targetHouse(r *http.Request, body *recogniseRequest) string {
	if h := strings.TrimSpace(r.URL.Query().Get("house_id")); h != "" {
		return h
	}
	return strings.TrimSpace(body.HouseID)
}

func (s *Server) handleRecognise(w http.ResponseWriter, r *http.Request) {
	if !s.requireSlate(w, r) {
		return
	}

	p, ok := principalFrom(r)
	if !ok || p == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no scribe in session"})
		return
	}

	// The request may confirm the session's house, but cannot select another.
	var body recogniseRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if named := targetHouse(r, &body); named != "" && !ownsHouse(p, named) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "a scribe may only act for the house they serve",
		})
		return
	}

	house := houseOf(p)
	writ, err := s.store.GrantCrownWrit(house, p.Username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such house"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not seal writ"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sealed":   true,
		"house":    writ.HouseID,
		"standing": "crown",
		"writ":     writ,
	})
}
