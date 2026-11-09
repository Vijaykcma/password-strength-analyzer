import math
import re
import secrets
import sqlite3
import string
import hashlib

# ---------------------------------------------------------
# 1. Database Setup (History Tracking / Prevention of Reuse)
# ---------------------------------------------------------
DB_NAME = "password_vault.db"

def init_db():
    """Initializes a local SQLite database to store password hashes."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    """Computes a SHA-256 hash for secure storage and comparison."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def is_password_reused(username: str, password: str) -> bool:
    """Checks whether the password has already been used by the user."""
    pwd_hash = hash_password(password)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM password_history WHERE username = ? AND password_hash = ?",
        (username, pwd_hash)
    )
    result = cursor.fetchone()
    conn.close()
    return result is not None

def record_password(username: str, password: str):
    """Saves a newly approved password hash to history."""
    pwd_hash = hash_password(password)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO password_history (username, password_hash) VALUES (?, ?)",
        (username, pwd_hash)
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------
# 2. Strength, Entropy, & Complexity Evaluation
# ---------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "admin", "qwerty",
    "password123", "letmein", "welcome", "iloveyou", "pass1234"
}

def calculate_entropy(password: str) -> float:
    """
    Calculates information entropy (bits): E = L * log2(R)
    L = length, R = character pool size
    """
    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation)

    if pool_size == 0 or len(password) == 0:
        return 0.0

    return round(len(password) * math.log2(pool_size), 2)

def evaluate_password(password: str) -> dict:
    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[" + re.escape(string.punctuation) + r"]", password))
    is_common = password.lower() in COMMON_PASSWORDS
    unique_chars = len(set(password))

    entropy = calculate_entropy(password)

    # Base rule-based score (0 to 100)
    score = 0
    feedback = []

    if is_common:
        return {
            "verdict": "Very Weak",
            "score": 0,
            "length": length,
            "entropy": entropy,
            "feedback": ["This is a widely known, leaked common password. Do not use it."]
        }

    # Length scoring
    if length >= 14:
        score += 35
    elif length >= 10:
        score += 25
    elif length >= 8:
        score += 15
    else:
        feedback.append("Password is too short (minimum 8 characters, recommended 12+).")

    # Character variety scoring
    if has_lower:
        score += 15
    else:
        feedback.append("Add lowercase letters.")

    if has_upper:
        score += 15
    else:
        feedback.append("Add uppercase letters.")

    if has_digit:
        score += 15
    else:
        feedback.append("Add numeric digits (0-9).")

    if has_special:
        score += 20
    else:
        feedback.append("Add special symbols (!@#$%^&*).")

    # Repetition / uniqueness penalty
    if length > 0 and (unique_chars / length) < 0.6:
        score = max(0, score - 15)
        feedback.append("Too many repeated characters; increase uniqueness.")

    # Rating determination
    if score >= 85 and entropy >= 60:
        verdict = "Very Strong"
    elif score >= 65 and entropy >= 45:
        verdict = "Strong"
    elif score >= 45:
        verdict = "Moderate"
    else:
        verdict = "Weak"

    return {
        "verdict": verdict,
        "score": min(score, 100),
        "length": length,
        "entropy": entropy,
        "feedback": feedback
    }


# ---------------------------------------------------------
# 3. Strong Alternative Generator
# ---------------------------------------------------------
def generate_strong_alternative(length: int = 16) -> str:
    """Generates a cryptographically secure random password meeting all requirements."""
    chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+[]{}"),
    ]
    all_chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}"
    chars += [secrets.choice(all_chars) for _ in range(length - len(chars))]
    
    # Shuffle cryptographically to avoid predictable character positions
    shuffled = chars[:]
    for i in range(len(shuffled) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]

    return "".join(shuffled)


# ---------------------------------------------------------
# 4. Interactive Execution Interface
# ---------------------------------------------------------
def main():
    init_db()
    print("=" * 55)
    print("        PASSWORD STRENGTH ANALYZER & AUDITOR        ")
    print("=" * 55)

    username = input("Enter username: ").strip()
    if not username:
        username = "default_user"

    password = input("Enter password to evaluate: ")

    # Database reuse check
    if is_password_reused(username, password):
        print("\n[!] SECURITY ALERT: You have previously used this password.")
        print("    Password reuse across accounts or history is prohibited.")

    # Analysis
    result = evaluate_password(password)

    print("\n--- Evaluation Summary ---")
    print(f"Strength Verdict : {result['verdict']}")
    print(f"Overall Score    : {result['score']} / 100")
    print(f"Character Length : {result['length']}")
    print(f"Entropy          : {result['entropy']} bits")

    if result["feedback"]:
        print("\nRecommendations for Improvement:")
        for tip in result["feedback"]:
            print(f"  * {tip}")

    # Generate alternative if weak or requested
    if result["score"] < 70:
        print("\nGenerated Strong Alternative:")
        alt_pwd = generate_strong_alternative(16)
        print(f"  -> {alt_pwd}")
        print(f"     (Entropy: ~{calculate_entropy(alt_pwd)} bits)")

    # Save to history if acceptable
    if result["score"] >= 60 and not is_password_reused(username, password):
        record_password(username, password)
        print("\n[✓] Password meets acceptable thresholds and is saved to user history.")

if __name__ == "__main__":
    main()