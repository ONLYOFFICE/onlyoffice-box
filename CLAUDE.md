# ONLYOFFICE app for Box

A standalone service (not a Box plugin): 4 Go microservices on go-micro via
`github.com/ONLYOFFICE/onlyoffice-integration-adapters`. Details, design history and branches — see `HANDOVER.md`.

## Commands

```bash
git submodule update --init --recursive   # required: formats from ONLYOFFICE/document-formats
make build                                # → build/{auth,builder,callback,gateway}
make test                                 # go test -v -race ./...
make audit                                # vet + staticcheck + govulncheck + tests
make tidy                                 # go fmt + go mod tidy
make run/gateway                          # likewise run/auth, run/builder, run/callback
go test $(go list ./... | grep -v auth/web/core/adapter)   # without MongoDB
```

- The `services/auth/web/core/adapter` (Mongo) test needs MongoDB on `localhost:27017`, otherwise it fails on timeout.
- Smoke tests: `services/gateway/web/smoke_test.go`, `services/callback/web/controller/callback_smoke_test.go`,
  `services/builder/web/handler/build_smoke_test.go`.
- Run services from the repository root: the gateway serves `/static` from a relative path.

## Layout

```
services/
  gateway/   HTTP :4044 — Box OAuth, sessions, /editor, /convert, /api/users/*, /app/* (Desktop + AI)
             web/server.go — all routes; web/embeddable — HTML templates and locales (9 languages)
  auth/      RPC — Box tokens in MongoDB (AES keyed by the client secret), refresh 12 s before expiry
  builder/   RPC — DocEditor config (permissions, document key, JWT)
  callback/  HTTP :5044 — /callback from Docs, uploads a new version to Box
  shared/    BoxAPI client (client.go), configs, request/response, format (submodule formats/)
```

Services talk over go-micro RPC by the name `<namespace>:<service>`, e.g. `box:auth`.

## Configuration

- `services/<svc>/config/config.yml` is gitignored; the template is `config.example.yml`. Any field can be
  overridden by an environment variable (`CREDENTIALS_*`, `ONLYOFFICE_DS_*`, `STORAGE_URL`, `REGISTRY_*`, ...).
- auth reads the DB from the `storage:` key / `STORAGE_URL`; the `persistence:` key in the example config is stale and ignored.
- gateway: without `ONLYOFFICE_ALLOWED_DOWNLOADS` > 0 every conversion fails (semaphore with weight 0).

## Conventions

- Conventional commits: `fix(gateway): ...`, `feat: ...`, `chore(deps): ...`, `docs: ...`.
- Branches: work in `feature/*` / `fix/*` → PR into `develop` → release PR `develop` → `master`.
  origin is git.onlyoffice.com (Gitea).
- Apache 2.0 license header "(c) Copyright Ascensio System SIA <year>" in every .go file.
- Version = the first `## x.y.z` in CHANGELOG.md (CI reads it) + `version:` in config.example.yml.
- Add new UI strings to every `services/gateway/web/embeddable/locales/*.json`.

## Don'ts

- Never commit or write secrets to files: config.yml, the Box client secret, the Docs JWT secret, connection strings.
- Don't remove `actsAsSessionUser` or the `user` check in `SessionMiddleware.Protect`: the user id from state/body
  decides whose Box token the service uses.
- Don't change the document key formula (`hash(modifiedAt + fileID)`): co-editing breaks.
- Don't change what the encryption/signing keys are derived from (the client secret): all stored tokens become undecryptable.
- Don't enable redirect following in the Box client: the download link is taken from `Location`.
- Don't commit or push unless explicitly asked.
