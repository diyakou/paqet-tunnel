package httpapi

import (
	"encoding/json"
	"net/http"

	"kypaqet-license-bot/internal/store"
)

type API struct {
	st store.Store
}

func New(st store.Store) *API {
	return &API{st: st}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/v1/activate", a.handleActivate)
	return mux
}

type activateReq struct {
	License  string `json:"license"`
	ServerID string `json:"server_id"`
}

func (a *API) handleActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req activateReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, store.ActivateResult{OK: false, Reason: "bad_json"})
		return
	}
	res, err := a.st.Activate(req.License, req.ServerID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, store.ActivateResult{OK: false, Reason: "server_error"})
		return
	}
	status := http.StatusOK
	if !res.OK {
		status = http.StatusForbidden
	}
	writeJSON(w, status, res)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
