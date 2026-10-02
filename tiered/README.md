# Scenario Sketchbook with sync

One Python file (`server.py`) serves the app (`index.html`) and stores your projects in SQLite.
The page also works on its own (it keeps data in the browser). When it's served by `server.py`,
a **Sync** button appears.

## Run it

    pip install -r requirements.txt
    python server.py set-password        # 10+ characters; stored as a salted hash
    python server.py run                 # http://127.0.0.1:8765

Open the address, click **Sync**, sign in, then **Push to server**.

## Using it from another computer

Don't expose the plain port to the internet. Pick one:

* **Tailscale (simplest):** run the server on a machine in your tailnet, then `tailscale serve --bg 8765`.
  Only your own devices can reach it, over HTTPS.
* **Reverse proxy with HTTPS** (Caddy, nginx) in front of `127.0.0.1:8765`. Start the server with
  `SKETCHBOOK_TRUST_PROXY=1` so rate limiting sees real client addresses.

The login cookie is `Secure`, so browsers only send it over HTTPS (or on `localhost`). For testing over plain
`http://` on another address, set `SKETCHBOOK_INSECURE_COOKIES=1`. Not for real use.

## How sync works

* Every push becomes a numbered revision, stored whole. The revision list is the journal.
* Each push carries an automatic summary ("edited component “Ryzen 5”; added group “Snacks”") and an optional note.
* A push only succeeds if you started from the latest revision. Otherwise the server answers 409 and the page offers:
  **Keep mine and push on top**, **Keep both** (server version saved as a separate local project), or **Take theirs**.
* **Restore as copy** turns any past revision into a separate local project. Nothing is deleted from the journal.
* States shown: *in sync*, *local changes*, *server is newer*, *conflict*, *not pushed*.

## What protects your data

* Password login (salted hash), session cookie that is HttpOnly, SameSite=Strict, and Secure.
* Login rate limit: 5 wrong passwords, then a growing lockout.
* Writes also need an `X-Sketchbook` header, a second defence against cross-site requests. No CORS is enabled.
* A strict Content-Security-Policy: the page may only talk to its own server, and it loads nothing from third parties.
* The data folder (`./data`, or `SKETCHBOOK_DATA`) is created owner-only; secret files are mode 0600.

## What it does not do

* **No end-to-end encryption.** Anyone with access to the server's disk can read your projects.
  Use disk encryption on that machine if that matters. Passphrase-based client-side encryption is possible later.
* **Single user, one password.** No accounts.
* **Whole-document sync.** No field-level merging; conflicts are resolved with the three choices above.

## Backups

Copy the `data` folder, or run `sqlite3 data/sketchbook.db ".backup backup.db"` while the server is running.
To sign out every device, delete `data/secret.key` and restart.

## API (JSON, all under /api; send header `X-Sketchbook: 1` on writes)

| Method | Path | Notes |
|---|---|---|
| GET | /health | no login needed |
| POST | /login, /logout | |
| GET | /projects | latest revision of each project |
| GET | /projects/{id}[?rev=N] | a project, optionally a past revision |
| GET | /projects/{id}/journal | revision history |
| POST | /projects/{id} | `{baseRev, doc, note, device, summary}` → `{rev}`, or 409 `{rev}` |
