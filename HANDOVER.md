# HANDOVER — ONLYOFFICE app for Box

## 1. Integration type

A **standalone service**, not a plugin inside Box (code). Box knows it as an app in the Box App Center
(`onlyoffice_personal`) with an "Open with ONLYOFFICE" web integration; the file opens in a new tab on the gateway domain.

| Service  | Port | Transport    | Role |
|----------|------|--------------|------|
| gateway  | 4044 | HTTP (chi)   | Box OAuth, sessions, editor/convert pages, invitations, `/app/*` for Desktop |
| auth     | 5052 | go-micro RPC | Box tokens in MongoDB, AES encryption keyed by the client secret, refresh |
| builder  | 6260 | go-micro RPC | signed DocEditor config: permissions, document key, callback URL |
| callback | 5044 | HTTP         | `/callback` from Docs → uploads a new version to Box |

The framework is `onlyoffice-integration-adapters` (fx + go-micro v4), the same one used by other ONLYOFFICE cloud
connectors (a comment mentioning "dropbox" is left in the code — it grew out of the Dropbox integration) (inference).

Infrastructure (from configs, code): Redis (cache, db 0/5, worker queue db 3), MongoDB (auth only), service registry,
broker, optional Zipkin. Type numbers in the adapters: registry `1`=Kubernetes, `2`=Consul, `3`=etcd, `4`/default=mDNS;
broker `1`=RabbitMQ, `2`=NATS, otherwise memory. The example uses Consul + RabbitMQ; judging by the k8s utilities
in the images, production runs in Kubernetes (inference; which registry prod uses — verify).

Interaction with ONLYOFFICE (code):
- **Docs Cloud** — a pre-configured ONLYOFFICE tenant; users configure nothing. Uses
  `web-apps/apps/api/documents/api.js?shardkey=`, the Conversion API `POST /converter?shardkey=`, and the callback.
  JWT is required (secret `ONLYOFFICE_DS_SECRET`). `shardkey` = the document key (for the sharded cloud).
- **Desktop Editors** — `/app` (the page calls `AscDesktopEditor.execCommand("portal:login")` and connects Box
  as a cloud), the Desktop AI agent: `/app/ai` (provider `box`, interface version `1`), `/app/token`, `/app/download`.
  `/app/*` is reachable only with the `AscDesktopEditor` UA or `?desktop=true` plus a session; CORS only for `onlyoffice://plugin`.

Versions: Box is SaaS, no versions. Minimum Docs/Desktop versions are not pinned in the code. The editor uses
`onOutdatedVersion` and `shardkey` → requires a current Docs Cloud; the AI endpoints need a Desktop whose AI agent
supports cloud interface v1 (verify the Desktop version number).

## 2. Key features

1. **Install / sign in**: `/oauth/install` → Box OAuth (scopes from `CREDENTIALS_SCOPES`) → `/oauth/redirect` →
   tokens stored in auth, cookie session (JWT, ~7 days, extended on every request).
2. **Opening and co-editing** OOXML and other editable formats from document-formats; edit/comment/download/print
   permissions come from Box permissions (edit = `can_upload` or owner).
3. **Viewing** the other supported formats (PDF, DJVU, ...). In view mode the document key is random.
4. **Conversion** (`/convert`): for non-OOXML files a choice page — open for viewing / create an OOXML copy next to
   the original (or in the root if the user is not the owner) / edit with possible loss. Password prompt for protected
   files, type selection for XML. CSV is not converted.
5. **Saving**: Docs → `/callback` (status 2) → new version in Box using the token of the first user in `users`.
6. **Invite on @mention**: the file owner invites up to 10 people (viewer/editor).
7. **Empty Google files** (gdoc/gsheet/gslides with size 0) open as an empty OOXML document.
8. **Localization**: en, de, es, fr, it, ja, pt-BR, ru, zh (language from the Box profile).
9. **ONLYOFFICE Desktop**: connecting Box as a cloud (1.2.0) and the Desktop AI agent with Box access (`feature/mcp`, unreleased).

## 3. Build

- **Go**: `go 1.25.8` in go.mod on `master` (the licenses CI uses 1.25). `develop` has moved to Go 1.26.9,
  adapters v0.2.0 and go-micro v5.
- **Submodule** `services/shared/format/formats` → `github.com/ONLYOFFICE/document-formats` (public).
  Embedded via `go:embed`; without `git submodule update --init` the build fails.
- **Dependencies**: none are private. `onlyoffice-integration-adapters` is fetched from `proxy.golang.org`; no `GOPRIVATE`
  needed (code). Changes to the adapters go to a separate ONLYOFFICE repository maintained by the same integrations team (inference).
- **Locally**: `make build`, `make run/<svc>`; config — copy `config.example.yml` to `config.yml` (gitignored).
  Requires Redis, MongoDB, a registry; for the full flow — a public HTTPS address for gateway/callback
  (Box OAuth redirect and the Docs callback), e.g. via a tunnel.
- **Config pitfalls** (code):
  - auth reads the DB from `storage.url` / `STORAGE_URL`; the `persistence:` key in the example is stale. Without a URL the service won't start.
  - `ONLYOFFICE_ALLOWED_DOWNLOADS` defaults to 0 → every conversion fails with `could not acquire semaphore`.
  - `callback.max_size` defaults to 20 MB (the example says 210 GB, looks like a typo).
- **Docker**: one `Dockerfile`, targets `gateway|auth|builder|callback`, images `onlyoffice/box-<svc>`.
  The runtime images include python3 + `requests`/`kubernetes`: added by DevOps (commit `dfeb017`, "utilities to check
  the availability of the k8s api") for k8s API availability checks during deployment — the Go code doesn't use them.
  The `services/gateway/static` directory is not copied into the image (see tech debt).
- **CI** (GitHub Actions, although origin is git.onlyoffice.com: the repository is mirrored to GitHub
  `ONLYOFFICE/onlyoffice-box`; secrets `DOCKER_HUB_USERNAME/ACCESS_TOKEN`, `BOX_WEBHOOK_URL/TOKEN` live in the GitHub
  repository settings, accessible to ONLYOFFICE GitHub org admins / DevOps (verify who exactly)).

Where production secrets live: not in the repository; Box client ID/secret — in the app's Box Developer Console;
the Docs JWT secret — with the Docs Cloud tenant owners; runtime values — in the k8s deployment secrets (inference, verify with DevOps).

## 4. Publishing

There is one marketplace — the **Box App Center** (listing `https://app.box.com/integrations/onlyoffice_personal/i`).
The code runs on our servers, so a regular release is a **deployment of the services**, not a new submission to Box:
Box review is needed only when the app listing/settings change (name, description, screenshots, scopes,
redirect URL, integration). There is also the page `https://www.onlyoffice.com/office-for-box` (ONLYOFFICE website).

Process (code + inference):
1. PR into `develop` → CI builds `onlyoffice/box-<svc>:<ver>-rc.<run>` and calls the `BOX_WEBHOOK_URL` webhook
   ("Update connector") — updates the test/staging environment (inference; where it points — verify with DevOps).
2. Release PR `develop` → `master` → CI creates the `v<ver>` tag and a GitHub Release from the CHANGELOG.
3. Production images with a non-`-rc` version — `workflow_dispatch` of build.yaml with tag `<ver>`, or `hooks/build`/`push`
   (Docker Hub autobuild by `DOCKER_TAG`, a leftover of the old scheme). Production rollout is done by DevOps (verify).
4. Manual steps in Box (only if the app changed): Box Developer Console → the app → changes →
   submit for App Center review. Timelines and typical rejection reasons are not recorded in the repository; in practice
   Box checks that the description matches the functionality, screenshots, privacy/terms/support links and minimal
   scopes (inference — verify against correspondence with Box).

## 5. Implicit knowledge

- **The Box client secret is the shared key for everything** (code): encrypting tokens in Mongo, signing the session JWT,
  the cookie codec, the CSRF key. Rotating the secret → all sessions reset, stored tokens can't be decrypted → every user
  goes through OAuth again. Do it only deliberately.
- **Cookie `SameSite=None; Secure; Partitioned`**: the session must work in a third-party
  context (Box opens the app, OAuth in a Box window/iframe, Desktop). `Partitioned` is needed so that
  Chrome doesn't block the third-party cookie. Don't remove without testing in Chrome and Desktop.
- **Document key** = md5(`modifiedAt + fileID`): all co-authors get the same key, and after saving to Box
  `modified_at` changes → a new session. In view mode — a random UUID (Docs cache doesn't interfere).
- **`singleflight` on `user:file`** merges double clicks/parallel requests for config, conversion, invitations.
- **`actsAsSessionUser`**: the user id in the editor `state` and in the conversion body must match
  the session; otherwise one could act with another user's token.
- **OAuth scopes**: only the non-empty scopes from the config go into the authorize URL.
- **The Box client doesn't follow redirects**: `files/{id}/content` answers 302 to a signed URL — that URL is what we need
  (for Docs and for `/app/download`). Retries only on 429.
- **Callback**: only status 2 is handled (document closed with changes); forcesave (6) and errors (3/7) are ignored —
  this has been so since the start of the project; forcesave is not enabled in the config. The upload uses the token of
  `users[0]`; a HEAD size check runs before downloading. The `state` in the callback URL is signed with the Docs secret (file ID and name).
- **Conversion**: the copy goes into the original's folder if the user created the file; otherwise into the root (`0`),
  because they may lack write access to someone else's folder. The copy's name gets a timestamp in the user's time zone.
- **`customization.plugins`** — was `false` from the first commit, so the web editor had no plugins and no AI.
  1.2.2 (`master`) enables them by omitting the field; `develop` still sets `false` until `master` is merged back.
- **Token refresh** 12 seconds before expiry (auth `select.go`); Box refresh tokens are single-use — concurrent
  refreshes for the same user could race (inference, not reproduced).
- **Desktop detection** by the `AscDesktopEditor` UA or `?desktop=true` is routing, not protection; the protection is the session.
- The session is extended on every protected request (a new 7-day JWT).

## 6. Known issues, tech debt, branches

### Branches

| Branch | State | Contents |
|--------|-------|----------|
| `master` | release 1.2.2 (plugins enabled) | + issue templates, README and 1.2.2 not present in `develop` → merge master into develop |
| `develop` | 1.2.1 + Go 1.26.9, adapters v0.2.0, **go-micro v5** | a large migration, unreleased — needs a full regression |
| `feature/mcp` | 10 commits on top of the pre-migration develop, unmerged | Desktop AI agent (`/app/ai`, `/app/token`, `/app/download`), MCP proxy removed, hardening: sessions, callback, user check, scopes. Conflicts with develop in go.mod. Candidate for 1.3.0 |
| `fix/plugins` | 1 commit from master | `plugins: true` — superseded by 1.2.2 in master, can be deleted |

Recommended order: master → develop; rebase `feature/mcp` onto develop → develop; full regression before the next release.

### Tech debt and bugs (code)

- `config.example.yml` lacks `allowed_downloads`, the `persistence:` key is stale, `max_size` is 210 GB.
- The gateway serves `/static` from a relative path, but the Dockerfile copies only the binary → icons 404 in the image;
  `favicon.ico` isn't even in the repository.
- `BuildGetInvitations` doesn't check that the user owns the file (Box itself checks the token's permissions).
- Box client errors by HTTP status are barely handled (resty doesn't return an error on 4xx/5xx).
- Few tests: smoke tests were added during the handover (see below), no end-to-end tests. The Mongo test needs a local Mongo.
- Formats depend on the document-formats submodule version — update together with a "formats update" CHANGELOG entry.

## 7. Plans and commitments

Recorded in the repository:
- Desktop AI agent with Box access (`feature/mcp`); interface v1 is defined by the Desktop AI agent (agreement with the Desktop team — verify).
- Release the adapters v0.2.0 / go-micro v5 / Go 1.26 migration already in `develop`.

There are no commitments to customers/partners (including Box) in the repository — verify with the integrations product manager.

## Manual verification checklist (before a release)

Cannot be automated: real Box OAuth, Docs Cloud, co-editing, Desktop.
On staging with a test Box account (preferably two):

1. [ ] Clean browser → Box → file → ⋮ → Integrations → Open with ONLYOFFICE → OAuth → the editor opens.
2. [ ] Reopen without OAuth (session alive). Chrome and Safari/Firefox (third-party cookies).
3. [ ] DOCX/XLSX/PPTX: edit → close the tab → after ~10 s a new version appears in Box.
4. [ ] Two users edit the same file at once and see each other's changes.
5. [ ] A user with view-only access → the editor opens in view mode.
6. [ ] PDF/DJVU → view.
7. [ ] DOC/ODT → the conversion page: "View", "Create OOXML" (copy appears in the right folder), "Edit with possible loss".
8. [ ] Password-protected DOC → password prompt; wrong password → error.
9. [ ] XML → document type selection.
10. [ ] @mention a user without access → invitation prompt → the invitation arrives in Box.
11. [ ] Empty Google Doc in Box → opens as an empty DOCX.
12. [ ] Box profile language (e.g. ru/de) → pages and the editor use that language.
13. [ ] Desktop: connect Box as a cloud → open a file → save.
14. [ ] Desktop AI agent (after `feature/mcp`): Box appears in the chat, the agent reads a file.
15. [ ] Service logs show no errors after the scenarios.

Automated smoke tests (`go test ./services/gateway/web ./services/callback/... ./services/builder/...`):
gateway routes and sessions, OAuth state, Desktop/AI access, callback signatures, permissions and key in the builder config.
