import re
import socket
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup


def extract_features(url):

    # ==========================================
    # NORMALIZE URL
    # ==========================================

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.netloc
    domain_without_port = domain.split(":")[0]
    path = parsed.path

    features = []

    # ==========================================
    # 1. having_IP_Address
    # ==========================================

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, domain_without_port):
        features.append(-1)
    else:
        features.append(1)

    # ==========================================
    # 2. URL_Length
    # ==========================================

    length = len(url)

    if length < 54:
        features.append(1)
    elif length <= 75:
        features.append(0)
    else:
        features.append(-1)

    # ==========================================
    # 3. Shortining_Service
    # ==========================================

    shortening_services = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly"
    ]

    if any(service in url.lower()
           for service in shortening_services):
        features.append(-1)
    else:
        features.append(1)

    # ==========================================
    # 4. having_At_Symbol
    # ==========================================

    if "@" in url:
        features.append(-1)
    else:
        features.append(1)

    # ==========================================
    # 5. double_slash_redirecting
    # ==========================================

    if url.startswith("https://"):
        remaining_url = url[8:]
    else:
        remaining_url = url[7:]

    if "//" in remaining_url:
        features.append(-1)
    else:
        features.append(1)

    # ==========================================
    # 6. Prefix_Suffix
    # ==========================================

    if "-" in domain_without_port:
        features.append(-1)
    else:
        features.append(1)

    # ==========================================
    # 7. having_Sub_Domain
    # ==========================================

    domain_parts = domain_without_port.split(".")

    if len(domain_parts) <= 2:
        features.append(1)
    elif len(domain_parts) == 3:
        features.append(0)
    else:
        features.append(-1)

   # ==========================================
   # 8. SSLfinal_State
   # ==========================================

   # HTTPS alone should NOT decide whether a URL
   # is legitimate or phishing.
   #
   # We use a neutral value here so that the model
   # considers the other URL characteristics.

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() == "https":
            try:
                response = requests.get(
                    url,
                    timeout=5,
                    verify=True,
                    allow_redirects=True
                )

                # HTTPS connection and valid SSL certificate
                features.append(1)

            except requests.exceptions.SSLError:
                # HTTPS but SSL certificate problem
                features.append(-1)

            except Exception:
                # HTTPS but SSL status could not be verified
                features.append(0)

        else:
            # HTTP does not provide SSL/TLS
            features.append(-1)

    except Exception:
        features.append(0)

    # ==========================================
    # 9. Domain_registeration_length
    # ==========================================

    # WHOIS information can be added later.
    features.append(0)

    # ==========================================
    # 10. Favicon
    # ==========================================

    # Favicon analysis can be improved later.
    features.append(0)

    # ==========================================
    # 11. port
    # ==========================================

    try:

        port = parsed.port

        if port is None:
            features.append(1)

        elif port in [80, 443]:
            features.append(1)

        else:
            features.append(-1)

    except ValueError:

        features.append(0)

    # ==========================================
    # 12. HTTPS_token
    # ==========================================

    if "https" in domain_without_port.lower():
        features.append(-1)
    else:
        features.append(1)

    # ==========================================
    # DOWNLOAD WEBPAGE
    # ==========================================

    html = ""
    soup = None
    response = None

    try:

        response = requests.get(
            url,
            timeout=5,
            headers={
                "User-Agent": "Mozilla/5.0"
            },
            allow_redirects=True
        )

        html = response.text

        soup = BeautifulSoup(
            html,
            "html.parser"
        )

    except Exception:

        html = ""
        soup = None
        response = None

    # ==========================================
    # 13. Request_URL
    # ==========================================

    if soup:

        images = soup.find_all("img")

        if len(images) == 0:

            features.append(1)

        else:

            external = 0

            for img in images:

                src = img.get("src", "")

                if (
                    src.startswith("http")
                    and domain_without_port not in src
                ):
                    external += 1

            ratio = external / len(images)

            if ratio < 0.22:
                features.append(1)

            elif ratio <= 0.61:
                features.append(0)

            else:
                features.append(-1)

    else:

        features.append(0)

    # ==========================================
    # 14. URL_of_Anchor
    # ==========================================

    if soup:

        anchors = soup.find_all("a")

        if len(anchors) == 0:

            features.append(0)

        else:

            suspicious = 0

            for anchor in anchors:

                href = anchor.get("href", "")

                if (
                    href.startswith("http")
                    and domain_without_port not in href
                ):
                    suspicious += 1

            ratio = suspicious / len(anchors)

            if ratio < 0.31:
                features.append(1)

            elif ratio <= 0.67:
                features.append(0)

            else:
                features.append(-1)

    else:

        features.append(0)

    # ==========================================
    # 15. Links_in_tags
    # ==========================================

    if soup:

        tags = soup.find_all(
            ["link", "script"]
        )

        if len(tags) == 0:

            features.append(1)

        else:

            external = 0

            for tag in tags:

                source = (
                    tag.get("src")
                    or tag.get("href")
                    or ""
                )

                if (
                    source.startswith("http")
                    and domain_without_port not in source
                ):
                    external += 1

            ratio = external / len(tags)

            if ratio < 0.17:
                features.append(1)

            elif ratio <= 0.81:
                features.append(0)

            else:
                features.append(-1)

    else:

        features.append(0)

    # ==========================================
    # 16. SFH
    # ==========================================

    if soup:

        forms = soup.find_all("form")

        if len(forms) == 0:

            features.append(1)

        else:

            suspicious = False

            for form in forms:

                action = form.get(
                    "action",
                    ""
                )

                if (
                    action == ""
                    or action == "about:blank"
                ):
                    suspicious = True

            if suspicious:
                features.append(-1)
            else:
                features.append(1)

    else:

        features.append(0)

    # ==========================================
    # 17. Submitting_to_email
    # ==========================================

    if soup:

        if "mailto:" in html.lower():
            features.append(-1)
        else:
            features.append(1)

    else:

        features.append(0)

    # ==========================================
    # 18. Abnormal_URL
    # ==========================================

    # Placeholder until WHOIS/domain analysis
    # is implemented.
    features.append(1)

    # ==========================================
    # 19. Redirect
    # ==========================================

    # A normal HTTP -> HTTPS redirect should NOT
    # automatically make a website phishing.
    #
    # Therefore, do not treat a simple protocol
    # redirect as a suspicious characteristic.

    try:

        if response and response.history:

            protocol_redirect_only = all(
                getattr(r, "status_code", 0) in [301, 302, 303, 307, 308]
                and r.url.split("://")[0].lower() == "http"
                and r.headers.get("Location", "").lower().startswith("https://")
                for r in response.history
            )

            if protocol_redirect_only:
                features.append(1)
            else:
               features.append(-1)

        else:
            features.append(1)

    except Exception:

        features.append(0)

    # ==========================================
    # 20. on_mouseover
    # ==========================================

    if "onmouseover" in html.lower():
        features.append(-1)
    else:
        features.append(1)

    # ==========================================
    # 21. RightClick
    # ==========================================

    html_lower = html.lower()

    if (
        "event.button==2" in html_lower
        or "event.button == 2" in html_lower
        or "contextmenu" in html_lower
    ):
        features.append(-1)
    else:
        features.append(1)

    # ==========================================
    # 22. popUpWidnow
    # ==========================================

    if "window.open" in html_lower:
        features.append(-1)
    else:
        features.append(1)

    # ==========================================
    # 23. Iframe
    # ==========================================

    if soup:

        if soup.find("iframe"):
            features.append(-1)
        else:
            features.append(1)

    else:

        features.append(0)

    # ==========================================
    # 24. age_of_domain
    # ==========================================

    # WHOIS can be added later.
    features.append(0)

    # ==========================================
    # 25. DNSRecord
    # ==========================================

    try:

        socket.gethostbyname(
            domain_without_port
        )

        features.append(1)

    except Exception:

        features.append(-1)

    # ==========================================
    # 26. web_traffic
    # ==========================================

    # External traffic information can be
    # integrated later.
    features.append(0)

    # ==========================================
    # 27. Page_Rank
    # ==========================================

    # Placeholder.
    features.append(0)

    # ==========================================
    # 28. Google_Index
    # ==========================================

    # Placeholder.
    features.append(0)

    # ==========================================
    # 29. Links_pointing_to_page
    # ==========================================

    if soup:

        links = soup.find_all("a")

        if len(links) > 0:
            features.append(1)
        else:
            features.append(-1)

    else:

        features.append(0)

    # ==========================================
    # 30. Statistical_report
    # ==========================================

    features.append(0)

    # ==========================================
    # FINAL CHECK
    # ==========================================

    if len(features) != 30:

        raise ValueError(
            f"Expected 30 features, got {len(features)}"
        )

    return features


# =================================================
# STEP 3 - TEST FEATURE EXTRACTION
# =================================================

if __name__ == "__main__":

    test_urls = [
        "https://google.com",
        "http://google.com",
        "https://secure-paypal-login-example.com",
        "http://secure-paypal-login-example.com"
    ]

    print("\n========================================")
    print("PHISHING URL FEATURE TEST")
    print("========================================")

    for test_url in test_urls:

        print("\nURL:")
        print(test_url)

        try:

            result = extract_features(test_url)

            print("Number of features:")
            print(len(result))

            print("Extracted features:")
            print(result)

            print("Feature 8 - SSL/HTTPS:")
            print(result[7])

            print("Feature 30 - Statistical Report:")
            print(result[29])

        except Exception as e:

            print("ERROR:")
            print(e)

    print("\n========================================")
    print("TEST COMPLETED")
    print("========================================")