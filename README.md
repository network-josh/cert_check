# Certificate Tool

A Windows desktop tool for day-to-day PKI certificate work:

- Verify that a private key, certificate, CSR, and/or an old certificate all
  belong to the same key pair (MD5 modulus comparison)
- Generate RSA key pairs and CSRs with multiple Subject Alternative Names
- Build the SAN string for Microsoft PKI (ADCS) web enrollment
- Find chain/CA certificates that match a given leaf certificate
- Connect to a live host and run 15 TLS/certificate checks with a coloured
  dashboard and exportable report

All certificate operations use the Python `cryptography` library, which links
against OpenSSL on Windows. No separate OpenSSL installation is required.

---

## From Zero to Running on a Clean Windows Machine

### 1. Install Python

Download **Python 3.11 or newer** from <https://www.python.org/downloads/>.

During installation, check **"Add python.exe to PATH"** before clicking
Install Now.  Verify in a new terminal:

```
python --version
```

### 2. Get the tool

Download or clone this repository, then open a terminal in the `cert_check`
folder:

```
git clone <repo-url>
cd cert_check
```

Or extract the ZIP and `cd` into it.

### 3. Install dependencies

```
pip install -r requirements.txt
```

This installs three packages:

| Package        | Purpose                                                        |
|----------------|----------------------------------------------------------------|
| `cryptography` | All certificate operations (wraps OpenSSL)                     |
| `pyopenssl`    | Live TLS connections — full chain and OCSP staple retrieval    |
| `PySide6`      | Desktop UI framework                                           |

### 4. Run

```
python main.py
```

On first launch the tool creates `C:\Certs\` automatically.  All paths are
configurable in the **Settings** tab.

---

## Features

### Verify Set

Checks that a private key, certificate, CSR, and/or an old certificate all
belong to the same RSA key pair by computing the MD5 hash of each file's
public-key modulus.  Matching files will show the same hash.

**How to use**

- Use the four **Browse** buttons to load individual files (Old Certificate is
  useful when you want to confirm a renewed cert still matches the same key).
- Or click **Scan Folder** to auto-detect the first key, cert, and CSR found
  in a directory.
- Click **Verify Selected Files** to compare.

**Equivalent OpenSSL commands**

```bash
# Run all three and compare the output — they must match
openssl rsa  -modulus -noout -in server.key | openssl md5
openssl x509 -modulus -noout -in server.crt | openssl md5
openssl req  -modulus -noout -in server.csr | openssl md5
```

---

### Create CSR

Generates a new RSA private key and Certificate Signing Request with one or
more Subject Alternative Names baked in.

**How to use**

1. Enter the **Common Name** (e.g. `app.example.com`).
2. Click **Seed CN + www** to pre-populate the SAN list with the CN and
   `www.CN`, or type additional hostnames/IPs and click **Add**.
3. Choose a **Key Source**:
   - **Generate new key** — choose a key size (2048 or 4096 bits).  Optionally
     tick **Password-protect key** and enter a passphrase — this writes an
     additional `.enc.key` alongside the plain `.key`.
   - **Use existing key** — browse to an existing `.key` file.  If the key is
     encrypted a passphrase field appears automatically.
4. Choose Key Usage flags and Extended Key Usage.
5. Select an output directory (defaults to the value in Settings).
6. Click **Generate CSR + Key**.

Output files are named from the CN (e.g. `app.example.com.key`,
`app.example.com.csr`).  A DER-encoded copy of the CSR
(`app.example.com.csr.der`) is also written alongside the PEM file.

Subject fields (O, OU, C, ST, L) are pre-populated from **Subject defaults**
in Settings and can be overridden per-request.

Use **Save Template** to store a named combination of subject defaults, key
size, and usage flags for reuse.

**Equivalent OpenSSL commands**

```bash
# Without SANs
openssl req -new -newkey rsa:2048 -nodes \
    -keyout server.key \
    -out server.csr \
    -subj "/CN=app.example.com/O=Example Corp/ST=Kentucky/C=US"

# With SANs — create san.cnf first:
#
#   [req]
#   default_bits       = 2048
#   prompt             = no
#   distinguished_name = dn
#   req_extensions     = req_ext
#
#   [dn]
#   CN = app.example.com
#
#   [req_ext]
#   subjectAltName = @alt_names
#
#   [alt_names]
#   DNS.1 = app.example.com
#   DNS.2 = www.app.example.com
#   IP.1  = 192.0.2.10

openssl req -new -newkey rsa:2048 -nodes \
    -keyout server.key \
    -out server.csr \
    -config san.cnf

# Encrypt the private key after generation
openssl rsa -in server.key -aes256 -out server.enc.key
```

---

### SAN Generator

Loads an existing CSR, extracts its Common Name, and lets you build a SAN
list to paste into the **Microsoft PKI (ADCS) web enrollment** interface.

Output format: `san:dns=app.example.com&dns=www.app.example.com&ip=192.0.2.10`

**How to use**

1. Click **Load CSR** to open a CSR file.
2. Add any additional SANs in the text box and click **Add SAN**.
3. Click **Generate SAN String** then **Copy to Clipboard**.
4. Paste into the "Additional Attributes" field in the ADCS web enrollment UI.

**Equivalent OpenSSL commands**

There is no OpenSSL command that produces the MS PKI attribute string.  To
inspect SANs already present in a CSR:

```bash
openssl req -text -noout -in server.csr | grep -A2 "Subject Alternative"
```

---

### Chain Helper

The Chain Helper tab has three sections that share a single loaded leaf
certificate.

#### Scan Local Folder

Scans a directory for certificates that could be chain certs for the loaded
leaf, ranked by:

- **Subject DN match** — the candidate's subject equals the leaf's issuer
- **AKI/SKI match** — the leaf's Authority Key Identifier matches the
  candidate's Subject Key Identifier

#### Build Chain via AIA

Automatically fetches and assembles the full certificate chain (intermediates +
root) by following the `caIssuers` URL in each certificate's Authority
Information Access (AIA) extension.

**How to use**

1. Load the leaf certificate.
2. Click **Build Chain**. The tool walks AIA URLs upward until it reaches a
   self-signed root, logging each download URL.
3. Choose an output directory (defaults to Settings → Default output directory).
4. Optionally tick **Include leaf certificate in output PEM**.
5. Click **Save Chain PEM** — the file is named `{CN}-chain.pem` and the path
   is automatically filled into the Validate section.

If a download fails the error message includes the exact URL and the manual
`curl` + `openssl` commands needed to fetch the file by hand.

#### Validate Chain

Validates a chain PEM file against the loaded leaf certificate. Checks:

| Check | What is verified |
|---|---|
| Chain connects to leaf | `chain[0]` subject matches leaf issuer (DN + AKI/SKI) |
| Correct order / no gaps | Each cert issued by the next |
| Root is self-signed | Last cert has `subject == issuer` |
| All CA certs have `cA=TRUE` | `basicConstraints` on every chain cert |
| No expired certificates | Every cert is within its validity window today |
| Cryptographic signatures | Each cert signature verified against issuer's public key |
| pathLenConstraint | Chain depth within declared limits |

> Checks **not** performed: CRL/OCSP revocation, name constraints, policy
> constraints.  For full RFC 5280 path validation use `openssl verify`.

The validation report is shown in a scrollable text panel. Use **Copy Report**
to copy it to the clipboard or **Export Report…** to save it as a `.txt` file
(default filename includes a timestamp).

**Equivalent OpenSSL commands**

```bash
# Verify leaf against a chain bundle
openssl verify -CAfile chain.pem leaf.crt

# Find the AIA caIssuers URL in a leaf cert
openssl x509 -in leaf.crt -text -noout | grep -A2 "CA Issuers"

# Manually download an intermediate cert (if AIA fetch fails)
curl -o intermediate.der <URL from AIA output>
openssl x509 -inform DER -in intermediate.der -out intermediate.pem

# Assemble the chain manually (nearest-to-leaf first)
cat intermediate.pem root.pem > chain.pem

# List all certs in a chain PEM
openssl crl2pkcs7 -nocrl -certfile chain.pem | openssl pkcs7 -print_certs -noout

# Verify one cert's signature against its issuer
openssl verify -partial_chain -CAfile issuer.pem cert.pem

# Show full chain presented by a live server
openssl s_client -connect hostname:443 -showcerts
```

---

### Site Verification

Connects to a live host over TLS and runs 15 checks.  The **Checks** panel
doubles as a colour-coded dashboard after each run — individual check labels and
group headers turn green / amber / red based on results.

**How to use**

1. Enter the **Hostname** (used for SNI and certificate name matching).
2. Optionally enter an **IP address** to connect directly without DNS (SNI still
   uses the hostname).
3. Adjust **Port** (default 443) and **Expiry warn** threshold.
4. Select which checks to run using the grouped checkboxes.  **All** at the top
   of each group is a select-all toggle.
5. Click **Run Checks**.  Results appear in the report panel; the checkbox labels
   update with their status colour simultaneously.
6. Use **Copy Report** or **Export Report…** to save the results as a `.txt`
   record.

**Checks performed**

| Group | Check | Pass condition |
|---|---|---|
| General | Certificate expiration | Not expired; warn if within threshold |
| General | SAN / CN match | Hostname covered by a SAN (or CN fallback) |
| General | Self-signed detection | Certificate has a distinct issuer |
| General | Full chain served | Server sends at least one intermediate |
| General | Chain order | Each cert issued by the next |
| Security | Trusted CA | Chain verified by system trust store |
| Security | Weak signature algorithm | Not SHA-1 or MD5 |
| Security | Key size | RSA ≥ 2048 bits, ECC ≥ 256 bits |
| Revocation | OCSP stapling | Staple present and valid (absent = configurable INFO/WARN) |
| Revocation | OCSP revocation | OCSP responder returns GOOD |
| Revocation | CRL revocation | Serial not in CRL |
| TLS Versions | TLS 1.0 rejected | Server rejects TLS 1.0 |
| TLS Versions | TLS 1.1 rejected | Server rejects TLS 1.1 |
| TLS Versions | TLS 1.2 supported | Server accepts TLS 1.2 |
| TLS Versions | TLS 1.3 supported | Server accepts TLS 1.3 (INFO if absent, not FAIL) |

TLS version probes show **SKIP** when the local OpenSSL has that version disabled
at the system level.

**Equivalent OpenSSL commands**

```bash
# Connect and show leaf certificate:
openssl s_client -connect example.com:443 -servername example.com < /dev/null

# Show full chain as served:
openssl s_client -connect example.com:443 -servername example.com -showcerts < /dev/null

# Check OCSP stapling:
openssl s_client -connect example.com:443 -servername example.com -status < /dev/null

# Probe a specific TLS version (-tls1 / -tls1_1 / -tls1_2 / -tls1_3):
openssl s_client -connect example.com:443 -servername example.com -tls1_2 < /dev/null

# OCSP revocation check:
openssl ocsp -issuer issuer.pem -cert leaf.pem -url <ocsp_url> -text -noverify
```

---

## Configuration

All settings live in the **Settings** tab and are saved to
`{base_dir}\cert_tool_app.json` (default `C:\Certs\cert_tool_app.json`).

| Setting                  | Default              | Description                                        |
|--------------------------|----------------------|----------------------------------------------------|
| Base directory           | `C:/Certs`           | Root for all other paths; see network-share note below |
| Log directory            | `C:/Certs/logs`      | Where daily log files are written (not yet wired)  |
| Default output directory | `C:/Certs`           | Where generated keys and CSRs are saved            |
| Templates directory      | `C:/Certs/templates` | Where CSR templates are stored as JSON             |
| Theme                    | light                | `light` or `dark`                                  |
| Show timestamps          | off                  | Prefix console lines with date/time                |
| Default key size         | 2048                 | RSA key size used when generating new CSRs         |
| Subject defaults         | (empty)              | Country, State, Locality, Org, OU pre-filled       |
| AIA fetch timeout        | 10                   | Seconds to wait per AIA caIssuers download         |
| Site check timeout       | 10                   | Seconds per network call in site verification      |
| Site expiry warn threshold | 30                 | Days remaining before expiry triggers a WARN       |
| OCSP staple absent       | INFO                 | Severity when server sends no OCSP staple (`INFO` or `WARN`) |

**Network share / roaming base directory** — if you change Base directory to a
UNC path or a non-default location, the new path is recorded in
`C:\Certs\cert_tool_basedir.txt`.  On subsequent launches the tool reads that
pointer file first so it can find the config in the alternate location without
any extra setup.

---

## Project Layout

```
cert_check/
├── main.py                Entry point
├── requirements.txt
├── core/
│   ├── app_config.py      Configuration load/save (all settings in one place)
│   ├── crypto_ops.py      PEM/DER loading, modulus extraction
│   ├── verify_set.py      Key/cert/CSR/old-cert MD5 match logic
│   ├── csr_ops.py         RSA key + CSR generation
│   ├── san_ops.py         SAN parsing and MS PKI string formatting
│   ├── csr_templates.py   Template persistence
│   ├── cert_inspector.py  Deep cert comparison (CN, SAN, expiry, extensions)
│   ├── chain_ops.py       AIA chain builder, chain validator, local folder scan
│   ├── site_ops.py        Live-site TLS checks (15 checks, report formatter)
│   └── errors.py          Exception types
├── ui/
│   ├── main_window.py     Main window and console log
│   ├── verify_tab.py      Verify Set tab
│   ├── csr_tab.py         Create CSR tab
│   ├── san_tab.py         SAN Generator tab
│   ├── chain_tab.py       Chain Helper tab
│   ├── site_tab.py        Site Verification tab
│   ├── settings_tab.py    Settings tab
│   └── types.py           Shared type stubs
└── archive/               Original single-file scripts (reference only)
```

---

## Notes

- Only RSA keys are fully supported for modulus matching.  ECDSA/EdDSA
  certificates can be loaded and inspected but will show `MD5: (unreadable)`.
- Encrypted private keys are auto-detected in every tab — a passphrase field
  appears automatically when one is loaded; no manual mode-switch is needed.
- The tool does not submit CSRs or connect to any CA automatically.
- Future goal: direct integration with F5, Palo Alto, Cisco, and similar
  network devices to validate and push certificates.
