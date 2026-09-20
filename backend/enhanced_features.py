import re
import math
from urllib.parse import urlparse


# ==========================================
# SUSPICIOUS KEYWORDS
# ==========================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "password",
    "bank",
    "payment",
    "confirm",
    "update",
    "wallet",
    "authenticate"
]


# ==========================================
# URL ENTROPY
# ==========================================

def calculate_entropy(text):

    if not text:
        return 0

    frequency = {}

    for character in text:
        frequency[character] = frequency.get(character, 0) + 1

    entropy = 0
    length = len(text)

    for count in frequency.values():

        probability = count / length

        entropy -= probability * math.log2(probability)

    return entropy


# ==========================================
# ENHANCED FEATURE EXTRACTION
# ==========================================

def extract_enhanced_features(url):

    # Add HTTP if protocol is missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    # Remove port number
    domain_without_port = domain.split(":")[0]

    path = parsed.path
    query = parsed.query

    features = []

    # ==========================================
    # 1. DOMAIN LENGTH
    # ==========================================

    domain_length = len(domain_without_port)

    features.append(domain_length)


    # ==========================================
    # 2. NUMBER OF DOTS
    # ==========================================

    number_of_dots = domain_without_port.count(".")

    features.append(number_of_dots)


    # ==========================================
    # 3. NUMBER OF HYPHENS
    # ==========================================

    number_of_hyphens = url.count("-")

    features.append(number_of_hyphens)


    # ==========================================
    # 4. NUMBER OF DIGITS
    # ==========================================

    number_of_digits = sum(
        character.isdigit()
        for character in url
    )

    features.append(number_of_digits)


    # ==========================================
    # 5. NUMBER OF SPECIAL CHARACTERS
    # ==========================================

    special_characters = sum(
        not character.isalnum()
        for character in url
    )

    features.append(special_characters)


    # ==========================================
    # 6. NUMBER OF SUBDOMAINS
    # ==========================================

    domain_parts = domain_without_port.split(".")

    if domain_parts[0] == "www":
        subdomain_count = max(len(domain_parts) - 3, 0)
    else:
        subdomain_count = max(len(domain_parts) - 2, 0)

    features.append(subdomain_count)


    # ==========================================
    # 7. NUMBER OF URL PARAMETERS
    # ==========================================

    if query:
        parameter_count = len(query.split("&"))
    else:
        parameter_count = 0

    features.append(parameter_count)


    # ==========================================
    # 8. NUMBER OF PATH SEGMENTS
    # ==========================================

    path_segments = [
        segment
        for segment in path.split("/")
        if segment
    ]

    features.append(len(path_segments))


    # ==========================================
    # 9. SUSPICIOUS KEYWORD COUNT
    # ==========================================

    url_lower = url.lower()

    keyword_count = 0

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url_lower:
            keyword_count += 1

    features.append(keyword_count)


    # ==========================================
    # 10. URL ENTROPY
    # ==========================================

    entropy = calculate_entropy(url)

    features.append(entropy)


    # ==========================================
    # 11. DIGIT / CHARACTER RATIO
    # ==========================================

    total_characters = len(url)

    if total_characters > 0:

        digit_ratio = (
            number_of_digits /
            total_characters
        )

    else:

        digit_ratio = 0

    features.append(digit_ratio)


    # ==========================================
    # 12. SPECIAL CHARACTER RATIO
    # ==========================================

    if total_characters > 0:

        special_ratio = (
            special_characters /
            total_characters
        )

    else:

        special_ratio = 0

    features.append(special_ratio)


    # ==========================================
    # RETURN 12 FEATURES
    # ==========================================

    return features


# ==========================================
# TEST
# ==========================================

if __name__ == "__main__":

    test_url = "https://secure-login-example.com/verify/account"

    print("\n================================")
    print("ENHANCED FEATURE TEST")
    print("================================")

    print("URL:")
    print(test_url)

    features = extract_enhanced_features(test_url)

    print("\nEnhanced features:")
    print(features)

    print("\nNumber of enhanced features:")
    print(len(features))

    if len(features) == 12:
        print("\nSUCCESS!")
        print("Exactly 12 enhanced features extracted.")

    else:
        print("\nERROR!")
        print("Expected 12 features.")

    print("================================")