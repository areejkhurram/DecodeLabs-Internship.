import string

# A short blocklist of widely known weak/common passwords.
# In a real system this would be a much larger file or a breach-database lookup,
# but a local list is enough to demonstrate the concept.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "111111", "1234567", "iloveyou", "adobe123", "123123",
    "admin", "letmein", "welcome", "monkey", "login", "princess",
    "qwerty123", "solo", "passw0rd", "starwars", "dragon", "master",
    "hello", "freedom", "whatever", "qazwsx", "trustno1", "654321",
    "password1", "1234", "000000", "1q2w3e4r", "sunshine", "shadow",
    "football", "baseball", "123321", "harley", "jordan23",
}


def has_sequential_chars(password, run_length=3):
    """Detects runs like 'abcd' or '4321' of the given length or more."""
    for i in range(len(password) - run_length + 1):
        chunk = password[i:i + run_length]
        ascending = all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(len(chunk) - 1))
        descending = all(ord(chunk[j]) - ord(chunk[j + 1]) == 1 for j in range(len(chunk) - 1))
        if ascending or descending:
            return True
    return False


def has_repeated_chars(password, run_length=3):
    """Detects the same character repeated, e.g. 'aaa' or '111'."""
    for i in range(len(password) - run_length + 1):
        if len(set(password[i:i + run_length])) == 1:
            return True
    return False


def check_password_strength(password):
    """
    Scores a password from 0-100 based on length, character variety,
    and penalizes common passwords and weak patterns (repeats/sequences).
    Returns: (strength_label, score, details_dict)
    """

    length = len(password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_symbol = any(char in string.punctuation for char in password)
    is_common = password.lower() in COMMON_PASSWORDS
    has_sequence = has_sequential_chars(password)
    has_repeat = has_repeated_chars(password)

    score = 0

    # --- Length scoring ---
    if length >= 8:
        score += 15
    if length >= 12:
        score += 10
    if length >= 16:
        score += 10

    # --- Character variety scoring ---
    score += 15 if has_upper else 0
    score += 15 if has_lower else 0
    score += 15 if has_digit else 0
    score += 15 if has_symbol else 0

    # --- Penalties for weak patterns ---
    if has_sequence:
        score -= 15
    if has_repeat:
        score -= 15

    # Clamp score to 0-100
    score = max(0, min(100, score))

    # --- Final classification ---
    if length < 8 or is_common:
        # Hard fail: too short or a known weak/leaked password,
        # regardless of how the rest of the score looks.
        strength = "Weak"
    elif score < 40:
        strength = "Weak"
    elif score < 70:
        strength = "Medium"
    elif score < 90:
        strength = "Strong"
    else:
        strength = "Very Strong"

    details = {
        "Length (8+ characters)": length >= 8,
        "Uppercase letter": has_upper,
        "Lowercase letter": has_lower,
        "Digit": has_digit,
        "Symbol": has_symbol,
        "Not a common/leaked password": not is_common,
        "No sequential characters (e.g. abcd, 4321)": not has_sequence,
        "No repeated characters (e.g. aaa, 111)": not has_repeat,
    }

    return strength, score, details


def display_result(password, strength, score, details):
    print(f"\nPassword entered: {'*' * len(password)}")
    print(f"Score: {score}/100")
    print(f"Strength: {strength}")
    print("Checklist:")
    for criterion, passed in details.items():
        mark = "PASS" if passed else "FAIL"
        print(f"  [{mark}] {criterion}")


def main():
    print("=== Password Checker ===")
    while True:
        password = input("\nEnter a password to check (or press Enter to quit): ")
        if not password:
            print("Goodbye!")
            break
        strength, score, details = check_password_strength(password)
        display_result(password, strength, score, details)


if __name__ == "__main__":
    main()