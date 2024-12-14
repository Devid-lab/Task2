import re

def check_length(password):
    if len(password) < 8:
        return False, "Password is too short. It should be at least 8 characters long."
    return True, ""

def check_complexity(password):
    if not re.search(r'[A-Z]', password):
        return False, "Password should contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password should contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password should contain at least one digit."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password should contain at least one special character."
    return True, ""

def check_uniqueness(password):
    common_patterns = [
        r'123', r'abc', r'password', r'qwerty', r'letmein', r'admin',
        r'welcome', r'princess', r'solo', r'love', r'monkey', r'football'
    ]
    for pattern in common_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            return False, "Password contains a common pattern. Avoid using common words or sequences."
    return True, ""

def password_strength_checker(password):
    length_valid, length_message = check_length(password)
    complexity_valid, complexity_message = check_complexity(password)
    uniqueness_valid, uniqueness_message = check_uniqueness(password)

    if not length_valid:
        return "Weak", length_message
    if not complexity_valid:
        return "Medium", complexity_message
    if not uniqueness_valid:
        return "Medium", uniqueness_message

    return "Strong", "Password is strong."

password = "P@ssw0rd123"
strength, message = password_strength_checker(password)
print(f"Strength: {strength}\nMessage: {message}")