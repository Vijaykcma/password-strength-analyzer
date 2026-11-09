# Password Strength Analyzer & Security Auditor

A cybersecurity tool developed in Python to evaluate the strength and resilience of user-entered passwords against brute-force and dictionary attacks. The tool implements mathematical information entropy calculation, rule-based complexity checks, common breach detection, secure alternative suggestions, and an SQLite database to prevent password reuse.

---

## Features

- **Entropy-Based Strength Calculation:** Measures brute-force resistance in bits using the Shannon entropy formula:
  $$E = L \times \log_2(R)$$
  *(where $L$ is the password length and $R$ is the character pool size).*
- **Complexity & Character Variety Checks:** Validates the presence of:
  - Lowercase characters (`a-z`)
  - Uppercase characters (`A-Z`)
  - Numeric digits (`0-9`)
  - Special symbols (`!@#$%^&*...`)
- **Uniqueness & Repetition Detection:** Flags character repetition and heavily repeated patterns.
- **Leaked & Common Password Blocklist:** Instantly identifies common weak passwords (e.g., `admin`, `123456`, `password`).
- **Cryptographically Secure Alternative Generator:** Uses Python's CSPRNG `secrets` module to generate high-entropy ($>100\text{ bits}$), 16-character replacement passwords.
- **Password History & Anti-Reuse (Database Integration):** Connects to a local SQLite database (`password_vault.db`) that stores one-way SHA-256 hashes, preventing users from reusing previous passwords without storing plaintext credentials.

---

## Project Structure

```text
.
├── password_analyzer.py    # Main application logic
├── password_vault.db       # Local SQLite database (auto-generated on first run)
└── README.md               # Project documentation
