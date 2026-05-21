import re
import math
import hashlib
import getpass
from datetime import datetime


COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123",
    "admin", "letmein", "welcome", "football", "iloveyou",
    "monkey", "dragon", "password123", "qwerty123", "admin123",
    "passw0rd", "p@ssword", "p@ssw0rd"
}


LEETSPEAK_MAP = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "!": "i"
}


def normalize_leetspeak(password):
    normalized = ""

    for char in password.lower():
        normalized += LEETSPEAK_MAP.get(char, char)

    return normalized


def calculate_entropy(password):
    charset_size = 0

    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(not c.isalnum() for c in password):
        charset_size += 32

    if charset_size == 0:
        return 0

    return round(len(password) * math.log2(charset_size), 2)


def estimate_crack_time(entropy):
    guesses_per_second = 1_000_000_000
    seconds = (2 ** entropy) / guesses_per_second

    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds / 86400:.2f} days"
    else:
        return f"{seconds / 31536000:.2f} years"


def has_keyboard_pattern(password):
    patterns = [
        "qwerty", "asdf", "zxcv", "1234", "abcd",
        "qwertyuiop", "asdfgh", "zxcvbn"
    ]

    password_lower = password.lower()

    return any(pattern in password_lower for pattern in patterns)


def has_repeated_chars(password):
    return bool(re.search(r"(.)\1\1", password))


def has_sequential_chars(password):
    sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789"
    ]

    password_lower = password.lower()

    for sequence in sequences:
        for i in range(len(sequence) - 3):
            if sequence[i:i + 4] in password_lower:
                return True

    return False


def check_policy(password):
    policy_results = {
        "Minimum 12 characters": len(password) >= 12,
        "Has uppercase letter": bool(re.search(r"[A-Z]", password)),
        "Has lowercase letter": bool(re.search(r"[a-z]", password)),
        "Has number": bool(re.search(r"\d", password)),
        "Has special character": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\[\]]", password)),
        "No keyboard pattern": not has_keyboard_pattern(password),
        "No repeated characters": not has_repeated_chars(password),
        "No sequential characters": not has_sequential_chars(password)
    }

    return policy_results


def analyze_password(password):
    score = 0
    feedback = []

    if len(password) >= 16:
        score += 30
    elif len(password) >= 12:
        score += 25
    elif len(password) >= 8:
        score += 15
    else:
        feedback.append("Use at least 12 characters.")

    if re.search(r"[A-Z]", password):
        score += 15
    else:
        feedback.append("Add uppercase letters.")

    if re.search(r"[a-z]", password):
        score += 15
    else:
        feedback.append("Add lowercase letters.")

    if re.search(r"\d", password):
        score += 15
    else:
        feedback.append("Add numbers.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\[\]]", password):
        score += 20
    else:
        feedback.append("Add special characters.")

    password_lower = password.lower()
    normalized_password = normalize_leetspeak(password)

    if password_lower in COMMON_PASSWORDS:
        score -= 40
        feedback.append("This is a common password.")

    if normalized_password in COMMON_PASSWORDS and normalized_password != password_lower:
        score -= 30
        feedback.append("Leetspeak weakness detected, such as P@ssw0rd → password.")

    if has_keyboard_pattern(password):
        score -= 20
        feedback.append("Avoid keyboard patterns like qwerty or 1234.")

    if has_repeated_chars(password):
        score -= 10
        feedback.append("Avoid repeated characters like aaa or 111.")

    if has_sequential_chars(password):
        score -= 15
        feedback.append("Avoid sequential characters like abcd or 1234.")

    entropy = calculate_entropy(password)

    if entropy >= 80:
        score += 10
    elif entropy < 40:
        score -= 15
        feedback.append("Password entropy is low.")

    score = max(0, min(score, 100))

    return score, feedback, entropy


def password_rating(score):
    if score >= 85:
        return "Very Strong"
    elif score >= 70:
        return "Strong"
    elif score >= 50:
        return "Moderate"
    elif score >= 30:
        return "Weak"
    else:
        return "Very Weak"


def generate_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()


def export_report(score, rating, entropy, crack_time, feedback, policy_results, sha256_hash):
    filename = "password_analysis_report.txt"

    with open(filename, "w") as file:
        file.write("Password Strength Analysis Report\n")
        file.write("=" * 40 + "\n")
        file.write(f"Date: {datetime.now()}\n\n")

        file.write(f"Score: {score}/100\n")
        file.write(f"Rating: {rating}\n")
        file.write(f"Entropy: {entropy} bits\n")
        file.write(f"Estimated crack time: {crack_time}\n\n")

        file.write("Corporate Password Policy:\n")
        for rule, passed in policy_results.items():
            status = "PASS" if passed else "FAIL"
            file.write(f"- {rule}: {status}\n")

        file.write("\nRecommendations:\n")
        if feedback:
            for item in feedback:
                file.write(f"- {item}\n")
        else:
            file.write("- No major issues found.\n")

        file.write("\nSHA-256 Hash Demo:\n")
        file.write(sha256_hash + "\n")

    return filename


def main():
    print("=== Password Strength Analyzer ===")

    password = getpass.getpass("Enter a password to analyze: ")

    score, feedback, entropy = analyze_password(password)
    rating = password_rating(score)
    crack_time = estimate_crack_time(entropy)
    policy_results = check_policy(password)
    sha256_hash = generate_sha256(password)

    print("\n=== Results ===")
    print(f"Score: {score}/100")
    print(f"Rating: {rating}")
    print(f"Entropy: {entropy} bits")
    print(f"Estimated crack time: {crack_time}")

    print("\n=== Corporate Password Policy ===")
    for rule, passed in policy_results.items():
        status = "PASS" if passed else "FAIL"
        print(f"{rule}: {status}")

    print("\n=== Recommendations ===")
    if feedback:
        for item in feedback:
            print(f"- {item}")
    else:
        print("No major issues found.")

    print("\n=== SHA-256 Hash Demo ===")
    print(sha256_hash)

    report = export_report(
        score,
        rating,
        entropy,
        crack_time,
        feedback,
        policy_results,
        sha256_hash
    )

    print(f"\nReport exported to: {report}")


if __name__ == "__main__":
    main()