package main

import (
	"log"
	"net/http"

	"github.com/bokwoon95/erro"
	"github.com/bokwoon95/pagemanager-data/pagemanager"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

func main() {
	pm, err := pagemanager.New()
	if err != nil {
		log.Fatalln(erro.Sdump(err))
	}
	mux := chi.NewRouter()
	mux.Use(middleware.Compress(5))
	mux.Use(pm.Middleware)
	mux.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<h1>hello world</h1>"))
	})
	pm.ListenAndServe(":80", mux)
}
