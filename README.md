# SecFES — Secure File Encryption Software

A multithreaded file encryption/decryption tool written in C, using POSIX threads and OpenSSL's EVP API (AES-256-CBC).

I wrote SecFES in 2023 as an undergraduate project to learn systems programming: concurrency, synchronization, and calling a real cryptographic library. In 2026 I went back over it as a security engineer and wrote down its design flaws (see [Security Review](#security-review-2026)). Re-reading old code with a security mindset is part of what this repo is meant to show.

> ⚠️ **Not for real use.** The security review below lists known cryptographic weaknesses. Treat this as a learning project, not a tool for protecting sensitive data.

---

## Features

- **AES-256-CBC encryption/decryption** through OpenSSL's high-level `EVP_*` interface (PKCS#7 padding handled by OpenSSL).
- **Worker thread pool** of 10 POSIX threads. Workers pull jobs from a shared task list, synchronized with a `pthread_mutex_t` and a `pthread_cond_t`.
- **Two input modes**: a list of files passed on the command line, or every file in one folder.
- **Two key sources**: a key passed on the command line (`-k`) or read from a key file (`-K`).
- **Timing**: reports total wall-clock processing time using `CLOCK_MONOTONIC`.
- **Optional daemon mode**: a `daemonize()` routine (fork, `setsid`, `chdir("/")`, standard streams redirected to `/dev/null`). It is disabled by default; uncomment the call in `main()` to enable it.

## How it works

```
parse arguments ──► load key ──► build task list (files / folder entries)
                                           │
                     ┌─────────────────────┼─────────────────────┐
                     ▼                     ▼                     ▼
                 worker 0              worker 1      ...     worker 9
          lock mutex → take next task index → unlock
          encrypt/decrypt file (EVP) → lock → completed++ → signal cond
                     │                     │                     │
                     └──────────── pthread_join all ─────────────┘
                                           ▼
                                  print elapsed time
```

Each worker takes the next unclaimed task index while holding the mutex, then releases the lock **before** the expensive crypto work, so up to 10 files are processed in parallel. When no tasks remain, workers wake each other through the condition variable and exit cleanly.

## Build

Requires a C compiler, `make`, and OpenSSL development headers.

```bash
# Debian/Ubuntu
sudo apt install build-essential libssl-dev
# macOS (Homebrew)
brew install openssl

make
```

On macOS, if the OpenSSL headers aren't found:
```bash
make CFLAGS="-I$(brew --prefix openssl)/include" LDFLAGS="-L$(brew --prefix openssl)/lib"
```

## Usage

```
./secfes -k <key>      -e|-d  file1 file2 ... fileN   # encrypt/decrypt listed files
./secfes -K <keyfile>  -e|-d  file1 file2 ... fileN
./secfes -k <key>      -E|-D  <folder>                # encrypt/decrypt every file in a folder
./secfes -K <keyfile>  -E|-D  <folder>
./secfes -help
```

The key must be exactly **256 characters** (or a 256-byte key file). Example:

```bash
# generate a 256-character key file (128 random bytes, hex-encoded)
head -c 128 /dev/urandom | xxd -p | tr -d '\n' > key.txt

echo "hello world" > test.txt
./secfes -K key.txt -e test.txt   # encrypts in place
./secfes -K key.txt -d test.txt   # decrypts in place
cat test.txt
```

Files are **overwritten in place**, so try it on copies first.

---

## Security Review (2026)

I looked back at the original code from an attacker's point of view. These are the issues I found, roughly from most to least serious:

| # | Issue | Why it matters | Fix |
|---|-------|----------------|-----|
| 1 | **Hard-coded, reused IV** (`"0123456789012345"`) | In CBC mode, a fixed IV under the same key means identical plaintexts (and identical prefixes) produce identical ciphertexts, which leaks information. | Generate a fresh random IV per file with `RAND_bytes()` and store it in front of the ciphertext. |
| 2 | **No integrity/authentication** | CBC only provides confidentiality. An attacker can tamper with the ciphertext (for example bit-flipping) and nothing detects it. | Switch to AES-256-GCM (authenticated encryption), or add encrypt-then-MAC with HMAC-SHA256. |
| 3 | **Key derivation and handling** | The key is a 256-character string, but AES-256 uses only the first 32 bytes, so most of the input is ignored and the help text ("32-byte key") is inconsistent with the check. A human-chosen string is not a uniformly random key, and passing it with `-k` exposes it in `ps` and shell history. | Derive the key from a passphrase with a KDF (PBKDF2/scrypt/Argon2) and a salt, or require exactly 32 random bytes from a key file. Remove `-k`. Wipe key buffers with `OPENSSL_cleanse()`. |
| 4 | **Unchecked return values** | The return values of `EVP_*Init/Update/Final`, `fread`, and `malloc` are not checked. A failed decryption (wrong key, bad padding) can still write partial or garbage output over the file. | Check every call and abort without touching the original file on failure. |
| 5 | **Non-atomic in-place overwrite** | The file is opened with `"wb"` (truncated) before the new data is written. A crash or error at that point destroys the data. | Write to a temporary file, `fsync`, then `rename()` over the original. |
| 6 | **Whole file loaded into memory** | `malloc(size)` of the entire file doesn't scale to large files, and the result is never checked. | Stream the file in fixed-size chunks through `EVP_*Update`. |
| 7 | **Minor correctness issues** | Folder mode is single-level and doesn't skip subdirectories; the file limit is hard-coded at 20; elapsed time is computed in milliseconds but printed as "seconds"; `strdup`'d paths are never freed. | Use `nftw()` or `stat()` checks, a dynamic task queue, and fix the units and cleanup. |

### What I took away from it
The program *worked*: files went in, ciphertext came out, decryption round-tripped. It was still insecure in ways no functional test would catch. Using a cryptographic library correctly matters as much as using a strong algorithm, and "it runs" is not the same as "it's safe." That gap is why I care about adversarial testing.

## Tech stack
C (C99) · POSIX threads · OpenSSL libcrypto (EVP API) · Linux/macOS

## Author
Sean (Haoxiang) Cheng — MS in Information Technology – Information Security, Carnegie Mellon University
