# password-strength-analyzer
A cybersecurity tool built in Python that evaluates password resilience using mathematical information entropy ($E = L \cdot \log_2(R)$) and rule-based heuristics, generates cryptographically secure alternatives using CSPRNG (secrets), and enforces password history tracking via SQLite with SHA-256 hashing to prevent reuse.
