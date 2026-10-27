# CLISecretsharing

A CLI tool for system administrators and DevOps teams to protect "break-the-glass" codes, master passwords, and sensitive recovery keys using **Shamir's Secret Sharing (SSS)** algorithm.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Installation](#installation)
  - [Debian / Ubuntu Package (.deb)](#debian--ubuntu-package-deb)
  - [Build From Source](#build-from-source)
  - [Build .deb Package Locally](#build-deb-package-locally)
- [Usage](#usage)
  - [1. Generating Shares (`--generate`)](#1-generating-shares---generate)
  - [2. Recomposing the Secret (`--compose`)](#2-recomposing-the-secret---compose)
- [CLI Reference](#cli-reference)
- [Real-World Use Case](#real-world-use-case)
- [Security](#security)
- [License](#license)

---

## Overview

In critical infrastructure and systems administration, certain credentials (such as root passwords, disaster recovery keys, or emergency break-the-glass codes) must not be entrusted to a single individual, nor stored in plaintext in a single location.

**CLISecretsharing** implements a *(k, n)* threshold scheme based on Shamir's Secret Sharing:
- **n (Share Amount):** The secret is split into *n* distinct shares, distributed among trusted stakeholders.
- **k (Threshold):** Any *k* of these shares are sufficient to reconstruct the original secret.
- **Information-Theoretic Security:** Possessing fewer than *k* shares reveals absolutely no information about the underlying secret.

---

## How It Works

The application operates over a finite field using the standard large secp256k1 prime:
`0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F`

1. **Share Generation:**
   - The input secret string is converted into a large integer (`BigInt`).
   - A random polynomial of degree `k - 1` is constructed where the constant term `a0` is the secret.
   - *n* points `(x, f(x))` on the polynomial are evaluated, where `x` ranges from 1 to `n`.
   - Each point represents an individual share in the format `<id>:<value>`.

2. **Secret Reconstruction (Composition):**
   - Given at least *k* shares `(x_i, y_i)`, the application uses Lagrange interpolation over the prime field to recover the polynomial's constant term (the original secret).
   - The recovered integer is converted back into UTF-8 bytes to restore the original string.
   - If shares are provided without explicit IDs (raw values), the tool automatically tests permutations of share IDs within the configured range to identify the valid printable secret.

---

## Installation

### Debian / Ubuntu Package (.deb)

Pre-built Debian packages are built automatically by GitHub Actions on every release and commit:

1. Download the latest `.deb` package from GitHub Releases or workflow artifacts.
2. Install with `dpkg`:
```bash
sudo dpkg -i clisecretsharing_*_amd64.deb
sudo apt-get install -f  # resolves any missing dependencies if needed
```

Once installed, the command is available system-wide as both `clisecretsharing` and `CLISecretsharing`:
```bash
clisecretsharing --help
```

### Build From Source

#### Prerequisites
- [Rust and Cargo](https://rustup.rs/) (edition 2024 or later)

```bash
git clone https://github.com/devlorenz/CLISecretsharing.git
cd CLISecretsharing
cargo build --release
```
The executable binary will be available at `./target/release/CLISecretsharing`.

### Build .deb Package Locally

If you have [cargo-deb](https://github.com/kornelski/cargo-deb) installed:
```bash
cargo install cargo-deb
cargo deb
sudo dpkg -i target/debian/clisecretsharing_*_amd64.deb
```

---

## Usage

### 1. Generating Shares (`--generate`)

Split a secret into *n* shares with a threshold of *k*:

```bash
cargo run -- -g -t <THRESHOLD> -s <SHARE_AMOUNT> -v "<SECRET>"
```

#### Example:
Split a break-the-glass password into 5 shares requiring any 3 to restore:

```bash
cargo run -- -g -t 3 -s 5 -v "Emergency-Root-Password-2026!"
```

Output:
```text
Generated shares:
1:8027750199480344553209503386314363052095059441469973434842735574605803191879
2:34555385315957453288999974800654956878369560800143962712212370000939005962366
3:79719789934770572103673828482196259378882500003411400227225868943120716755398
4:27728874818603505573660079422250362700363892385631721940425648393242100899312
5:110166818442088644546100697638193082549353707278086055930726876367120827737434
```

Distribute each share to a different trustee (e.g., share 1 to Admin A, share 2 to Admin B, etc.).

---

### 2. Recomposing the Secret (`--compose`)

Combine at least *k* shares to recover the secret:

```bash
cargo run -- -c -t <THRESHOLD> -v <SHARE_1> <SHARE_2> ... <SHARE_K>
```

#### Supported Share Formats:
- **Colon-delimited (standard):** `1:802775...`
- **Hyphen-delimited:** `1-802775...`
- **Raw value (without ID):** `802775...` (The tool automatically searches ID permutations to find the secret)

#### Example (using any 3 shares, e.g., 2, 4, and 5):
```bash
cargo run -- -c -t 3 -v \
  "2:34555385315957453288999974800654956878369560800143962712212370000939005962366" \
  "4:27728874818603505573660079422250362700363892385631721940425648393242100899312" \
  "5:110166818442088644546100697638193082549353707278086055930726876367120827737434"
```

Output:
```text
Original value: Emergency-Root-Password-2026!
```

---

## CLI Reference

| Flag / Option | Short | Description | Required In |
|---|---|---|---|
| `--generate` | `-g` | Activates share generation mode | Either `-g` or `-c` |
| `--compose` | `-c` | Activates secret recovery/composition mode | Either `-g` or `-c` |
| `--threshold <NUM>` | `-t` | Minimum number of shares required to reconstruct the secret (threshold k) | Both `-g` and `-c` |
| `--share-amount <NUM>` | `-s` | Total number of shares to generate (n), or maximum ID search range in composition | Required in `-g`, optional in `-c` |
| `--value <VAL>...` | `-v` | Secret string (in `-g`) or share strings / values (in `-c`) | Both `-g` and `-c` |
| `--help` | `-h` | Prints help information | Optional |
| `--version` | `-V` | Prints version | Optional |

---

## Real-World Use Case

1. **Setup:** A production database master key or root credential is created.
2. **Splitting:** The security lead generates 5 shares with a threshold of 3 (`-t 3 -s 5`).
3. **Distribution:** The 5 shares are securely delivered to 5 different team leads / executives.
4. **Emergency:** In a disaster recovery event, any 3 of the 5 leads present their shares to reconstruct the master key. No single person or pair of individuals can access the secret alone.

---

## Security

For security policies, vulnerability reporting guidelines, and operational considerations, please see [SECURITY.md](SECURITY.md).

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
