# SFTP Encrypted File → Dialer DB (FastAPI)

A small FastAPI service that reads a GPG/PGP-encrypted CSV file from an SFTP
server **directly into memory**, decrypts it **in memory**, validates the rows,
and saves them to a Dialer MySQL database.

The encrypted file is **never downloaded** (no `sftp.get()`, no `/tmp/file.gpg`,
no `./downloads/`). The decrypted CSV is **never written to disk**.

```text
POST /process-file
  → connect + authenticate SFTP (password, host key verified)
  → sftp.open(remote_file, "rb") → read encrypted bytes into memory
  → SHA-256 of the encrypted bytes → check sftp_file_history
        already SUCCESS? → STOP (409, nothing inserted)
  → GPG decrypt in memory
  → pandas.read_csv(io.StringIO(...)) → validate columns → clean rows
  → PROCESS_MODE=preview → PRINT to console, return counts (no DB)
  → PROCESS_MODE=save    → INSERT rows + history SUCCESS in ONE transaction → COMMIT
                           (any error → ROLLBACK + history FAILED)
```

---

## 1. Project structure

```text
sftp_fastapi/
├── app/
│   ├── __init__.py
│   ├── main.py            FastAPI app, endpoints, pipeline, error → HTTP mapping
│   ├── config.py          Reads/validates .env (secrets hidden from repr)
│   ├── sftp_service.py    connect_sftp(), read_remote_file() with paramiko
│   ├── decrypt_service.py decrypt_data(bytes) -> str with python-gnupg
│   ├── processor.py       CSV read/validate/transform + preview printing
│   ├── dialer_db.py       connect_db(), insert_records(), history table
│   └── logger.py          Logging setup (no secrets, no customer data)
├── .env                   Your real values (git-ignored)
├── .env.example           Template
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 2. Server requirement: GPG executable

`python-gnupg` is only a Python wrapper. It starts the real `gpg` program
installed on the server and talks to it through pipes (stdin/stdout). Without
`gpg` installed, decryption cannot work.

```bash
sudo apt update
sudo apt install gnupg
gpg --version
```

GPG needs a keyring folder (default `~/.gnupg`, or `GPG_HOME`). This is the
only local GPG data used; the encrypted and decrypted file content is passed
through pipes and never written there.

---

## 3. Installation

```bash
cd sftp_fastapi
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 4. Environment setup (`.env`)

```bash
cp .env.example .env
chmod 600 .env        # only the service user can read secrets
nano .env
```

| Variable | Required | Meaning |
|---|---|---|
| `SFTP_HOST` | yes | SFTP server host name or IP |
| `SFTP_PORT` | no (22) | SFTP port |
| `SFTP_USERNAME` | yes | SFTP login user |
| `SFTP_PASSWORD` | yes, unless `SFTP_PRIVATE_KEY` is set | SFTP login password |
| `SFTP_PRIVATE_KEY` | no | SSH private key file, used when the server asks for a key after the password (e.g. `/root/.ssh/sbi_sftp_key`) |
| `SFTP_PRIVATE_KEY_PASSPHRASE` | no | Passphrase of that key, if it has one |
| `SFTP_INTERACTIVE_RESPONSE` | no | Answer for the keyboard-interactive prompt the server may show after the password (default: `SFTP_PASSWORD`) |
| `SFTP_LOGIN_ORDER` | no | Login order for key + password servers, e.g. `publickey,keyboard-interactive`. Empty = `publickey,keyboard-interactive,password`. One connection, one login attempt per run |
| `SFTP_REMOTE_FILE` | yes | Full remote path. `{date:%d%m%Y}` is replaced by today's date, e.g. `/FROM_SBICMASCALL01/MAS_AHM_CD3_FAT_S_HB_TEST_{date:%d%m%Y}.csv.gpg`. `POST /process-file?file_date=2026-10-03` runs another day |
| `SFTP_DATE_UTC_OFFSET` | no (+05:30) | Time zone for "today" in the file name (server clock is UTC) |
| `SFTP_KNOWN_HOSTS` | no | known_hosts file used to verify the server (default `~/.ssh/known_hosts`) |
| `SFTP_STRICT_HOST_KEY_CHECKING` | no (true) | `true` = refuse unknown/changed servers. Keep `true` in production |
| `SFTP_TIMEOUT_SECONDS` | no (30) | Connect/handshake/auth timeout |
| `SFTP_MAX_FILE_MB` | no (200) | Refuse files bigger than this (file is held in memory) |
| `GPG_PASSPHRASE` | depends | Symmetric passphrase **or** private-key passphrase (see §5) |
| `GPG_HOME` | no | Keyring folder. Empty = `~/.gnupg` of the service user |
| `FILE_ENCODING` | no (utf-8-sig) | Text encoding of the decrypted CSV (`latin-1`, `cp1252`, …) |
| `DIALER_DB_HOST` | save mode | MySQL host |
| `DIALER_DB_PORT` | no (3306) | MySQL port |
| `DIALER_DB_USER` | save mode | MySQL user |
| `DIALER_DB_PASSWORD` | save mode | MySQL password |
| `DIALER_DB_NAME` | save mode | Database name |
| `DIALER_TARGET_TABLE` | save mode | Table where CSV rows are inserted |
| `HISTORY_TABLE` | no | Processing-history table (default `sftp_file_history`) |
| `PROCESS_MODE` | no (preview) | `preview` = decrypt + read + **print only**. `save` = insert into DB |
| `PREVIEW_ROWS` | no (20) | Rows printed in preview mode (`0` = all) |
| `API_KEY` | no | If set, `/process-file`, `/status`, `/history` need header `X-API-Key` |
| `LOG_LEVEL` | no (INFO) | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `LOG_FILE` | no | Also write logs to this file, e.g. `app.log` |

The app refuses to start if a required value is missing and reports the
variable **names** (never the values).

### Trust the SFTP server's host key (one time)

```bash
ssh-keyscan -p 22 sftp.example.com >> ~/.ssh/known_hosts
# verify the fingerprint with your SFTP provider:
ssh-keygen -lf ~/.ssh/known_hosts
```

### SSH key login (e.g. SBI)

The public half of the key must already be registered with the SFTP provider.
paramiko cannot read PuTTY `.ppk` files, so convert the original `.ppk` once
(it asks for the key passphrase; the output stays encrypted with it):

```bash
puttygen sbi_key.ppk -O private-openssh -o sbi_sftp_key
# Windows without puttygen CLI: PuTTYgen → Load → Conversions → Export OpenSSH key
mkdir -p /opt/sftp_fastapi/keys && mv sbi_sftp_key /opt/sftp_fastapi/keys/
chmod 700 /opt/sftp_fastapi/keys && chmod 600 /opt/sftp_fastapi/keys/sbi_sftp_key
```

Then in `.env`:

```text
SFTP_PRIVATE_KEY=/opt/sftp_fastapi/keys/sbi_sftp_key
SFTP_PRIVATE_KEY_PASSPHRASE=<passphrase of the .ppk>
SFTP_PASSWORD=<only if the server also asks for a password>
```

Keep key files outside the repo. Always copy the `.ppk` as a file: never paste
it through Excel/Sheets, which turns lines starting with `+`/`=`/`-` into `#NAME?`.

---

## 5. GPG setup: two different kinds of encryption

Ask the file sender which one they use. **`GPG_PASSPHRASE` alone is only
enough for password-based (symmetric) files.**

### A) Password-based (symmetric) GPG

The sender ran something like `gpg -c file.csv`.

```text
encrypted file
     ↓
passphrase (GPG_PASSPHRASE)
     ↓
decrypted data
```

Setup: put the shared passphrase in `GPG_PASSPHRASE`. No key import needed.

### B) Public/private key GPG (most common for SFTP partners)

You gave the sender your **public** key; they ran `gpg -e -r you@company.com file.csv`.

```text
encrypted file
     ↓
private key (must be imported into the keyring)
     ↓
private-key passphrase (GPG_PASSPHRASE)
     ↓
decrypted data
```

Setup (one time, as the same Linux user that runs the service):

```bash
# optional dedicated keyring
mkdir -p /opt/sftp_fastapi/gnupg && chmod 700 /opt/sftp_fastapi/gnupg
gpg --homedir /opt/sftp_fastapi/gnupg --import private_key.asc
gpg --homedir /opt/sftp_fastapi/gnupg --list-secret-keys
# then in .env:  GPG_HOME=/opt/sftp_fastapi/gnupg
#                GPG_PASSPHRASE=<passphrase of that private key>
```

Delete the `private_key.asc` file after import. If the private key has no
passphrase, leave `GPG_PASSPHRASE` empty.

Notes:
- If the private key is missing you get `the private key for this file is not in the GPG keyring`.
- `gpg-agent` may cache a correct passphrase for a while; to force a re-check run
  `gpgconf --homedir <GPG_HOME> --kill gpg-agent`.
- On some GnuPG 2.1/2.2 servers, passphrases passed by programs need
  `allow-loopback-pinentry` in `<GPG_HOME>/gpg-agent.conf` (then kill gpg-agent).

---

## 6. Dialer database setup

The history table is created automatically (needs `CREATE` permission once).
You can also create it yourself:

```sql
CREATE TABLE IF NOT EXISTS sftp_file_history (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    file_name     VARCHAR(255)    NOT NULL,
    file_hash     CHAR(64)        NOT NULL,
    record_count  INT UNSIGNED    NOT NULL DEFAULT 0,
    status        VARCHAR(20)     NOT NULL,          -- SUCCESS / FAILED
    processed_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    error_message VARCHAR(500)    NULL,
    UNIQUE KEY uq_file_hash (file_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

The target table (`DIALER_TARGET_TABLE`, e.g. `sbi_records`) is also created
automatically from the `SbiRecord` model in `app/models.py`: one `VARCHAR(255)`
column per SBI header (exact names, values stored exactly as in the file),
plus `id`, `source_file` (the file each row came from) and `created_at`.
To add a column SBI starts sending, add it to `SbiRecord.COLUMNS` and run
`ALTER TABLE sbi_records ADD COLUMN new_col VARCHAR(255) NULL;`
(columns not in the model are skipped with a warning).

Least-privilege DB user:

```sql
CREATE USER 'dialer_import'@'%' IDENTIFIED BY 'strong-password';
GRANT SELECT, INSERT, UPDATE, CREATE ON dialer.sftp_file_history TO 'dialer_import'@'%';
GRANT INSERT, CREATE ON dialer.sbi_records TO 'dialer_import'@'%';
```

### CSV rules

Set at the top of `app/processor.py`. `COLUMN_MAPPING = None` keeps every CSV
column with its own (trimmed, lower-cased) header name; all rows are kept and
values are only trimmed. The run stops if a column in
`REQUIRED_SOURCE_COLUMNS` (default `account_no`) is missing.

---

## 7. Run FastAPI

```bash
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Use **one worker** (the default). The service prevents parallel runs inside
one process; the DB transaction also locks the file's history row.

## 8. Swagger UI

Open **http://localhost:8000/docs** to see and try every endpoint.
(If `API_KEY` is set, add the `x-api-key` header value in Swagger.)

---

## 9. Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | `{"status": "ok"}` |
| POST | `/process-file` | Run the full flow once |
| GET | `/status` | Result of the last run since service start |
| GET | `/history?limit=20` | Rows from `sftp_file_history` |

### Test health

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

### Process file

```bash
curl -X POST http://localhost:8000/process-file
# with API_KEY set:
curl -X POST -H "X-API-Key: <API_KEY>" http://localhost:8000/process-file
```

**Preview mode** response (data is printed in the uvicorn terminal):

```json
{"status": "success", "mode": "preview", "file": "customer_data.csv.gpg",
 "file_hash": "de714a...", "columns": ["phone","name","city"],
 "records_read": 7, "records_valid": 3, "records_skipped": 4, "records_inserted": 0,
 "message": "Decrypted data printed to the server console. Nothing saved to DB."}
```

**Save mode** response:

```json
{"status": "success", "mode": "save", "file": "customer_data.csv.gpg",
 "file_hash": "de714a...", "records_read": 7, "records_valid": 3,
 "records_skipped": 4, "records_inserted": 3}
```

**Error** response:

```json
{"status": "error", "message": "Decryption failed: wrong GPG passphrase", "file": "customer_data.csv.gpg"}
```

### What happens after `POST /process-file`

1. Request is checked for the API key (if configured) and that no other run is active.
2. A TCP connection is opened to `SFTP_HOST:SFTP_PORT`, the SSH handshake runs,
   and the server's host key is compared with `known_hosts`.
3. The service logs in with `SFTP_USERNAME` / `SFTP_PASSWORD`.
4. `sftp.open(SFTP_REMOTE_FILE, "rb")` opens the file; its size is checked;
   all bytes are read into a Python `bytes` object. Remote file, SFTP channel
   and transport are closed in `finally`.
5. SHA-256 of the encrypted bytes is calculated.
6. Save mode: `sftp_file_history` is checked; if this hash already has
   `SUCCESS`, processing stops with HTTP 409 and nothing is inserted.
7. The bytes are piped to `gpg` and decrypted in memory.
8. pandas reads the text from `io.StringIO`, checks required columns, cleans rows.
9. Preview mode: raw lines + cleaned records are printed to the console; stop.
10. Save mode: one transaction inserts all rows (batches of 1000) and writes
    history `SUCCESS`, then `COMMIT`. On any DB error → `ROLLBACK`, no rows
    remain, and history is set to `FAILED` with a safe error message.
11. JSON result is returned.

### HTTP status codes

| Code | Situation |
|---|---|
| 200 | Success |
| 401 | Wrong/missing API key |
| 404 | Remote file not found |
| 409 | File already processed (duplicate) or another run is active |
| 422 | Not a GPG file, decryption failed, bad encoding, invalid CSV, missing columns, no valid rows |
| 500 | Insert failed (rolled back), target table missing, GPG not installed, config error |
| 502 | SFTP auth failure, connection failure, host key problem, read failure |
| 503 | Dialer DB connection/login failure |

---

## 10. Duplicate protection – what it does and doesn't cover

The hash is taken of the **encrypted bytes**, so the same uploaded file is never
imported twice (also if it is still on the SFTP server next time). GPG uses a
random session key, so if the sender **re-encrypts the same CSV**, the bytes and
hash are different and it will be imported again. If that can happen, also add a
unique key on the target table (for example on `phone` + a list/batch column).

A `FAILED` file can be retried: once it succeeds, its history row becomes `SUCCESS`.

---

## 11. Security checklist

- Secrets only in `.env` (git-ignored, `chmod 600`) or real environment variables.
- Logs contain steps, sizes, counts, hashes and MySQL error numbers only;
  never passwords, passphrases, file content or customer data. Third-party
  loggers (paramiko, gnupg, mysql) are limited to WARNING.
- API errors are fixed, safe messages; unexpected errors return `Internal server error`.
- **Preview mode prints customer data to the console.** Use it only for testing,
  then set `PROCESS_MODE=save`. If uvicorn output is captured by systemd/journald,
  preview output is captured too.
- Keep `SFTP_STRICT_HOST_KEY_CHECKING=true`.
- Set `API_KEY` if the port is reachable by anyone else, or bind to `127.0.0.1`.

## 12. Running automatically (optional)

Call the endpoint from cron, e.g. every 15 minutes:

```bash
*/15 * * * * curl -s -X POST -H "X-API-Key: <API_KEY>" http://127.0.0.1:8000/process-file >> /var/log/sftp_import_cron.log 2>&1
```

A file that was already imported returns 409 and inserts nothing.
