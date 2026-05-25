import re
import math
import hashlib
import getpass
from datetime import datetime


COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123",
    "admin", "letmein", "welcome", "football", "iloveyou",
    "monkey", "dragon", "password123", "qwerty123", "admin123",
    "passw0rd", "p@ssword", "p@ssw0rd", "welcome123", "letmein123"
}

LEETSPEAK_MAP = {
    "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"
}

ATTACK_SPEEDS = {
    "Online attack (100 guesses/sec)": 100,
    "Fast online attack (10,000 guesses/sec)": 10_000,
    "Offline GPU attack (1B guesses/sec)": 1_000_000_000,
    "Advanced cracking rig (100B guesses/sec)": 100_000_000_000
}


def normalize_leetspeak(password):
    return "".join(LEETSPEAK_MAP.get(char, char) for char in password.lower())


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


def format_time(seconds):
    if seconds < 1:
        return "less than 1 second"
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.2f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.2f} hours"
    if seconds < 31536000:
        return f"{seconds / 86400:.2f} days"
    if seconds < 31536000 * 1000:
        return f"{seconds / 31536000:.2f} years"

    return "1000+ years"


def estimate_attack_resistance(entropy):
    results = {}

    for attack_type, guesses_per_second in ATTACK_SPEEDS.items():
        total_guesses = 2 ** entropy
        average_seconds = total_guesses / guesses_per_second / 2
        results[attack_type] = format_time(average_seconds)

    return results


def has_keyboard_pattern(password):
    patterns = [
        "qwerty", "asdf", "zxcv", "1234", "abcd",
        "qwertyuiop", "asdfgh", "zxcvbn", "1q2w3e"
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


def has_year_pattern(password):
    return bool(re.search(r"(19\d{2}|20\d{2})", password))


def check_policy(password):
    return {
        "Minimum 12 characters": len(password) >= 12,
        "Has uppercase letter": bool(re.search(r"[A-Z]", password)),
        "Has lowercase letter": bool(re.search(r"[a-z]", password)),
        "Has number": bool(re.search(r"\d", password)),
        "Has special character": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\[\]]", password)),
        "No keyboard pattern": not has_keyboard_pattern(password),
        "No repeated characters": not has_repeated_chars(password),
        "No sequential characters": not has_sequential_chars(password),
        "No common year pattern": not has_year_pattern(password)
    }


def analyze_password(password):
    score = 0
    feedback = []
    score_breakdown = []

    if len(password) >= 16:
        score += 30
        score_breakdown.append("Length 16+ characters: +30")

    elif len(password) >= 12:
        score += 25
        score_breakdown.append("Length 12+ characters: +25")

    elif len(password) >= 8:
        score += 15
        score_breakdown.append("Length 8+ characters: +15")
        feedback.append(
            "Increase password length to at least 12 characters for stronger policy compliance."
        )

    else:
        feedback.append("Use at least 12 characters.")
        score_breakdown.append("Short password: +0")

    checks = [
        (r"[A-Z]", "Uppercase letters", 15, "Add uppercase letters."),
        (r"[a-z]", "Lowercase letters", 15, "Add lowercase letters."),
        (r"\d", "Numbers", 15, "Add numbers."),
        (r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\[\]]", "Special characters", 20, "Add special characters.")
    ]


    for pattern, label, points, message in checks:
        if re.search(pattern, password):
            score += points
            score_breakdown.append(f"{label}: +{points}")
        else:
            feedback.append(message)
            score_breakdown.append(f"{label}: +0")

    password_lower = password.lower()
    normalized_password = normalize_leetspeak(password)

    if password_lower in COMMON_PASSWORDS:
        score -= 40
        feedback.append("This is a common password.")
        score_breakdown.append("Common password penalty: -40")

    if normalized_password in COMMON_PASSWORDS and normalized_password != password_lower:
        score -= 30
        feedback.append("Leetspeak weakness detected, such as P@ssw0rd → password.")
        score_breakdown.append("Leetspeak weakness penalty: -30")

    if has_keyboard_pattern(password):
        score -= 20
        feedback.append("Avoid keyboard patterns like qwerty or 1234.")
        score_breakdown.append("Keyboard pattern penalty: -20")

    if has_repeated_chars(password):
        score -= 10
        feedback.append("Avoid repeated characters like aaa or 111.")
        score_breakdown.append("Repeated character penalty: -10")

    if has_sequential_chars(password):
        score -= 15
        feedback.append("Avoid sequential characters like abcd or 1234.")
        score_breakdown.append("Sequential character penalty: -15")

    if has_year_pattern(password):
        score -= 10
        feedback.append("Avoid predictable years like 2024, 2025, or birth years.")
        score_breakdown.append("Year pattern penalty: -10")

    entropy = calculate_entropy(password)

    if entropy >= 80:
        score += 10
        score_breakdown.append("High entropy bonus: +10")
    elif entropy < 40:
        score -= 15
        feedback.append("Password entropy is low.")
        score_breakdown.append("Low entropy penalty: -15")

    score = max(0, min(score, 100))

    return score, feedback, entropy, score_breakdown


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


def export_report(score, rating, entropy, attack_resistance, feedback, policy_results, sha256_hash, score_breakdown):
    filename = "password_analysis_report.txt"

    with open(filename, "w", encoding="utf-8") as file:
        file.write("Password Strength Analysis Report\n")
        file.write("=" * 45 + "\n")
        file.write(f"Date: {datetime.now()}\n\n")

        file.write(f"Score: {score}/100\n")
        file.write(f"Rating: {rating}\n")
        file.write(f"Entropy: {entropy} bits\n\n")

        file.write("Attack Resistance Estimates:\n")
        for attack_type, estimate in attack_resistance.items():
            file.write(f"- {attack_type}: {estimate}\n")

        file.write("\nScore Breakdown:\n")
        for item in score_breakdown:
            file.write(f"- {item}\n")

        file.write("\nCorporate Password Policy:\n")
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

    score, feedback, entropy, score_breakdown = analyze_password(password)
    rating = password_rating(score)
    attack_resistance = estimate_attack_resistance(entropy)
    policy_results = check_policy(password)
    sha256_hash = generate_sha256(password)

    print("\n=== Results ===")
    print(f"Score: {score}/100")
    print(f"Rating: {rating}")
    print(f"Entropy: {entropy} bits")

    print("\n=== Attack Resistance Estimates ===")
    for attack_type, estimate in attack_resistance.items():
        print(f"{attack_type}: {estimate}")

    print("\n=== Score Breakdown ===")
    for item in score_breakdown:
        print(f"- {item}")

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
        attack_resistance,
        feedback,
        policy_results,
        sha256_hash,
        score_breakdown
    )

    print(f"\nReport exported to: {report}")


if __name__ == "__main__":
    main()