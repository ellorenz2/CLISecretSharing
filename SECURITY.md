# Security Policy

## Disclaimer

**CLISecretsharing** is a simple open-source utility intended to help system administrators manage emergency break-the-glass credentials using Shamir's Secret Sharing.

This software is provided "as is", without warranty of any kind (as stated in the [LICENSE](LICENSE)). It has not undergone formal third-party cryptographic auditing or commercial certification. Please evaluate it against your organization's specific risk model before using it for critical production secrets.

---

## Supported Versions

Only the latest release / commit on the `main` branch receives security updates.

| Version | Supported |
|---|---|
| 0.1.x / `main` | :white_check_mark: |
| < 0.1.0 | :x: |

---

## Reporting a Vulnerability

If you discover a security issue or cryptographic flaw:

1. **Do not disclose it publicly:** Please do not open public issues or pull requests for sensitive security vulnerabilities.
2. **Contact:** Send an email to **devlorenz@virgilio.it** with a description of the issue.
3. **Include details:**
   - A summary of the vulnerability.
   - Steps or minimal proof of concept to reproduce it.
   - Potential impact or threat scenario.
4. **Response:** You will receive a response as soon as possible to discuss a fix and coordinate resolution.

---

## Operational Security Recommendations

When using this tool with sensitive credentials:

- **Shell History:** Passing secrets via the command-line argument (`-v "<secret>"`) may be recorded in shell history files (such as `~/.bash_history`) or visible in process listings (`ps`). Consider prefixing commands with a leading space (with `HISTCONTROL=ignorespace`) or clearing history after sensitive operations.
- **Isolated Distribution:** Distribute shares through distinct, independent, and encrypted channels so no single provider or interceptor can obtain `threshold` shares.
- **Secure Storage:** Advise each trustee to store their share in a secure location (e.g. encrypted password manager or secure vault).
