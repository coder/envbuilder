package mwtest

import "net/http"

func BasicAuthMW(username, password string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if username != "" || password != "" {
				authUser, authPass, ok := r.BasicAuth()
				if !ok || username != authUser || password != authPass {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
