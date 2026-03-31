# Certificate Tool

A Windows desktop tool for day-to-day PKI certificate work:

- Verify that a private key, certificate, CSR, and/or an old certificate all
  belong to the same key pair (MD5 modulus comparison)
- Generate RSA key pairs and CSRs with multiple Subject Alternative Names
- Build the SAN string for Microsoft PKI (ADCS) web enrollment
- Find chain/CA certificates that match a given leaf certificate

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

This installs two packages:

| Package        | Purpose                                      |
|----------------|----------------------------------------------|
| `cryptography` | All certificate operations (wraps OpenSSL)   |
| `PySide6`      | Desktop UI framework                         |

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
3. Choose key size, Key Usage flags, and Extended Key Usage.
4. Select an output directory (defaults to the value in Settings).
5. Optionally tick **Password-protect key** and enter a passphrase — this
   writes an additional `.enc.key` alongside the plain `.key`.
6. Click **Generate CSR + Key**.

Output files are named from the CN (e.g. `app.example.com.key`,
`app.example.com.csr`).

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

Loads a leaf certificate and scans a folder to find CA or intermediate
certificates that could be its issuer, ranked by:

- **Subject DN match** — the candidate's subject equals the leaf's issuer
- **AKI/SKI match** — the leaf's Authority Key Identifier matches the
  candidate's Subject Key Identifier

**Equivalent OpenSSL commands**

```bash
# Verify a certificate against a CA bundle
openssl verify -CAfile chain.pem leaf.crt

# Inspect issuer and Authority Key Identifier of a leaf cert
openssl x509 -in leaf.crt -text -noout | grep -A3 "Issuer\|Authority Key"

# Inspect Subject Key Identifier of a potential chain cert
openssl x509 -in intermediate.crt -text -noout | grep -A1 "Subject Key"

# Show full chain presented by a live server
openssl s_client -connect hostname:443 -showcerts
```

---

## Configuration

All settings live in the **Settings** tab and are saved to
`C:\Certs\cert_tool_app.json`.

| Setting                 | Default              | Description                                       |
|-------------------------|----------------------|---------------------------------------------------|
| Log directory           | `C:/Certs/logs`      | Where daily log files are written (not yet wired) |
| Default output directory| `C:/Certs`           | Where generated keys and CSRs are saved           |
| Templates directory     | `C:/Certs/templates` | Where CSR templates are stored as JSON            |
| Theme                   | light                | `light` or `dark`                                 |
| Show timestamps         | off                  | Prefix console lines with date/time               |
| Default key size        | 2048                 | RSA key size used when generating new CSRs        |
| Subject defaults        | (empty)              | Country, State, Locality, Org, OU pre-filled      |

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
│   ├── chain_ops.py       Chain certificate discovery
│   └── errors.py          Exception types
├── ui/
│   ├── main_window.py     Main window and console log
│   ├── verify_tab.py      Verify Set tab
│   ├── csr_tab.py         Create CSR tab
│   ├── san_tab.py         SAN Generator tab
│   ├── chain_tab.py       Chain Helper tab
│   ├── settings_tab.py    Settings tab
│   └── types.py           Shared type stubs
└── archive/               Original single-file scripts (reference only)
```

---

## Notes

- Only RSA keys are fully supported for modulus matching.  ECDSA/EdDSA
  certificates can be loaded and inspected but will show `MD5: (unreadable)`.
- The tool does not submit CSRs or connect to any CA automatically.
- Future goal: direct integration with F5, Palo Alto, Cisco, and similar
  network devices to validate and push certificates.
