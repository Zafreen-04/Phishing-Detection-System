import math
import re
from urllib.parse import urlparse


# =========================================================
# SUSPICIOUS KEYWORDS
# =========================================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "password",
    "passwd",
    "bank",
    "secure",
    "security",
    "payment",
    "update",
    "confirm",
    "confirmation",
    "wallet",
    "authenticate",
    "authentication",
    "billing",
    "invoice",
    "recover",
    "unlock"
]


# =========================================================
# BRAND KEYWORDS
# =========================================================

BRAND_KEYWORDS = [
    "google",
    "paypal",
    "microsoft",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "linkedin",
    "netflix",
    "whatsapp"
]


# =========================================================
# SUSPICIOUS TLDs
# =========================================================

SUSPICIOUS_TLDS = [
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "xyz",
    "click",
    "download",
    "zip"
]


# =========================================================
# SHANNON ENTROPY
# =========================================================

def calculate_entropy(text):

    if not text:
        return 0.0

    frequency = {}

    for character in text:
        frequency[character] = frequency.get(character, 0) + 1

    entropy = 0.0

    length = len(text)

    for count in frequency.values():

        probability = count / length

        entropy -= probability * math.log2(probability)

    return entropy


# =========================================================
# ADVANCED URL FEATURES
# =========================================================

def extract_advanced_features(url):

    # -----------------------------------------------------
    # Add scheme if missing
    # -----------------------------------------------------

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    # Complete URL
    url_text = url

    # -----------------------------------------------------
    # 1. URL length
    # -----------------------------------------------------

    url_length = len(url_text)

    # -----------------------------------------------------
    # 2. Hostname length
    # -----------------------------------------------------

    hostname_length = len(hostname)

    # -----------------------------------------------------
    # 3. Path length
    # -----------------------------------------------------

    path_length = len(path)

    # -----------------------------------------------------
    # 4. Query length
    # -----------------------------------------------------

    query_length = len(query)

    # -----------------------------------------------------
    # 5. Fragment length
    # -----------------------------------------------------

    fragment_length = len(fragment)

    # -----------------------------------------------------
    # 6. Path depth
    # -----------------------------------------------------

    path_depth = len([
        part for part in path.split("/")
        if part
    ])

    # -----------------------------------------------------
    # 7. Query parameter count
    # -----------------------------------------------------

    if query:
        query_parameter_count = len(query.split("&"))
    else:
        query_parameter_count = 0

    # -----------------------------------------------------
    # 8. Dot count
    # -----------------------------------------------------

    dot_count = url_text.count(".")

    # -----------------------------------------------------
    # 9. Hyphen count
    # -----------------------------------------------------

    hyphen_count = url_text.count("-")

    # -----------------------------------------------------
    # 10. Digit count
    # -----------------------------------------------------

    digit_count = sum(
        character.isdigit()
        for character in url_text
    )

    # -----------------------------------------------------
    # 11. Special character count
    # -----------------------------------------------------

    special_char_count = len(
        re.findall(
            r"[^a-zA-Z0-9]",
            url_text
        )
    )

    # -----------------------------------------------------
    # 12. Digit ratio
    # -----------------------------------------------------

    if len(url_text) > 0:
        digit_ratio = digit_count / len(url_text)
    else:
        digit_ratio = 0.0

    # -----------------------------------------------------
    # 13. Special character ratio
    # -----------------------------------------------------

    if len(url_text) > 0:
        special_char_ratio = (
            special_char_count / len(url_text)
        )
    else:
        special_char_ratio = 0.0

    # -----------------------------------------------------
    # 14. Hostname entropy
    # -----------------------------------------------------

    hostname_entropy = calculate_entropy(hostname)

    # -----------------------------------------------------
    # 15. Path entropy
    # -----------------------------------------------------

    path_entropy = calculate_entropy(path)

    # -----------------------------------------------------
    # 16. URL entropy
    # -----------------------------------------------------

    url_entropy = calculate_entropy(url_text)

    # -----------------------------------------------------
    # 17. Suspicious keyword count
    # -----------------------------------------------------

    url_lower = url_text.lower()

    suspicious_keyword_count = sum(
        1
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    )

    # -----------------------------------------------------
    # 18. Brand keyword count
    # -----------------------------------------------------

    brand_keyword_count = sum(
        1
        for brand in BRAND_KEYWORDS
        if brand in hostname.lower()
    )

    # -----------------------------------------------------
    # 19. Suspicious TLD
    # -----------------------------------------------------

    parts = hostname.lower().split(".")

    if len(parts) >= 2:

        tld = parts[-1]

    else:

        tld = ""

    suspicious_tld = (
        1 if tld in SUSPICIOUS_TLDS else 0
    )

    # -----------------------------------------------------
    # 20. Brand/domain mismatch
    # -----------------------------------------------------

    registered_domain = ""

    if len(parts) >= 2:

        registered_domain = (
            parts[-2] + "." + parts[-1]
        )

    brand_in_domain_mismatch = 0

    for brand in BRAND_KEYWORDS:

        if brand in hostname.lower():

            if brand not in registered_domain:

                brand_in_domain_mismatch = 1

            break

    # -----------------------------------------------------
    # FINAL FEATURE VECTOR
    # -----------------------------------------------------

    features = [

        url_length,
        hostname_length,
        path_length,
        query_length,
        fragment_length,
        path_depth,
        query_parameter_count,
        dot_count,
        hyphen_count,
        digit_count,
        special_char_count,
        digit_ratio,
        special_char_ratio,
        hostname_entropy,
        path_entropy,
        url_entropy,
        suspicious_keyword_count,
        brand_keyword_count,
        suspicious_tld,
        brand_in_domain_mismatch

    ]

    return features


# =========================================================
# TEST
# =========================================================

if __name__ == "__main__":

    test_urls = [

        "https://google.com",

        "https://example.com",

        "https://paypal-login-security.example.xyz",

        "https://secure-account-verification.example.top"

    ]

    for url in test_urls:

        print("\n====================================")
        print("URL:", url)
        print("====================================")

        features = extract_advanced_features(url)

        print("Number of features:", len(features))

        print("Features:")

        for index, value in enumerate(features, start=1):

            print(
                f"{index:02d}. {value}"
            )