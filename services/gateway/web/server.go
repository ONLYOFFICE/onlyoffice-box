/**
 *
 * (c) Copyright Ascensio System SIA 2023
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package web

import (
	"net/http"

	"github.com/ONLYOFFICE/onlyoffice-box/services/gateway/web/controller"
	"github.com/ONLYOFFICE/onlyoffice-box/services/gateway/web/middleware"
	shttp "github.com/ONLYOFFICE/onlyoffice-integration-adapters/service/http"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/csrf"
	"golang.org/x/oauth2"
)

type BoxHTTPService struct {
	mux               *chi.Mux
	authController    controller.AuthController
	editorController  controller.EditorController
	fileController    controller.FileController
	sessionMiddleware middleware.SessionMiddleware
	csrfMiddleware    func(http.Handler) http.Handler
}

// NewService initializes http server with options.
func NewServer(
	authController controller.AuthController,
	editorController controller.EditorController,
	fileController controller.FileController,
	sessionMiddleware middleware.SessionMiddleware,
	credentials *oauth2.Config,
) shttp.ServerEngine {
	service := BoxHTTPService{
		mux:               chi.NewRouter(),
		authController:    authController,
		editorController:  editorController,
		fileController:    fileController,
		sessionMiddleware: sessionMiddleware,
		csrfMiddleware: csrf.Protect(
			[]byte(credentials.ClientSecret),
			csrf.HttpOnly(true),
			csrf.Secure(true),
			csrf.SameSite(csrf.SameSiteNoneMode),
		),
	}

	return service
}

// ApplyMiddleware useed to apply http server middlewares.
func (s BoxHTTPService) ApplyMiddleware(middlewares ...func(http.Handler) http.Handler) {
	s.mux.Use(middlewares...)
}

// NewHandler returns http server engine.
func (s BoxHTTPService) NewHandler() interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
} {
	return s.InitializeServer()
}

// InitializeServer sets all injected dependencies.
func (s *BoxHTTPService) InitializeServer() *chi.Mux {
	s.InitializeRoutes()
	return s.mux
}

// InitializeRoutes builds all http routes.
func (s *BoxHTTPService) InitializeRoutes() {
	fs := http.FileServer(http.Dir("services/gateway/static"))
	s.mux.Group(func(r chi.Router) {
		r.Use(chimiddleware.Recoverer, chimiddleware.NoCache)

		r.Handle("/static/*", http.StripPrefix("/static/", fs))

		r.Route("/", func(cr chi.Router) {
			cr.Use(s.sessionMiddleware.Protect, s.csrfMiddleware)
			cr.Get("/editor", s.editorController.BuildGetEditor())
			cr.Get("/convert", s.fileController.BuildConvertPage())
			cr.Post("/convert", s.fileController.BuildConvertFile())
		})

		r.Route("/oauth", func(cr chi.Router) {
			cr.Get("/install", s.authController.BuildGetAuth())
			cr.Get("/redirect", s.authController.BuildGetRedirect())
		})

		r.NotFound(func(rw http.ResponseWriter, r *http.Request) {
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
		})
	})
}
