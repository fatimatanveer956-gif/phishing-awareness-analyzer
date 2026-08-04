"""
DecodeLabs Cybersecurity Internship
Project 3: Phishing Awareness Analysis
------------------------------------------
Goal: Analyze sample emails/messages to identify phishing attempts.

Key Requirements covered:
  - Identify suspicious links or keywords
  - List red flags found in phishing messages
  - Explain why the message is unsafe
"""

import re


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

URGENCY_PHRASES = [
    "act now", "urgent", "immediately", "verify your account",
    "your account has been suspended", "your account will be closed",
    "click here", "confirm your identity", "unusual activity detected",
    "limited time", "failure to respond", "final notice", "action required",
    "your account will be locked", "expire", "expires today",
]

CREDENTIAL_REQUEST_PHRASES = [
    "enter your password", "confirm your password", "your ssn",
    "social security number", "credit card number", "cvv", "pin number",
    "banking details", "login credentials", "update your payment",
    "wire transfer", "gift card",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer",
    "dear account holder", "dear sir/madam", "dear member",
]

SUSPICIOUS_TLDS = [".ru", ".tk", ".xyz", ".top", ".click", ".info", ".click"]

URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]

URL_PATTERN = re.compile(r"(https?://\S+|www\.\S+)", re.IGNORECASE)
IP_URL_PATTERN = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")


def find_urls(text: str):
    return URL_PATTERN.findall(text)


def analyze_links(urls):
    """Flags suspicious characteristics found in any links in the message."""
    flags = []
    for url in urls:
        lowered = url.lower()
        if IP_URL_PATTERN.match(url):
            flags.append(f"Link uses a raw IP address instead of a domain name: {url}")
        if any(shortener in lowered for shortener in URL_SHORTENERS):
            flags.append(f"Link uses a URL shortener, which hides the real destination: {url}")
        if any(lowered.rstrip("/").endswith(tld) for tld in SUSPICIOUS_TLDS):
            flags.append(f"Link uses an uncommon/high-risk domain ending: {url}")
        if lowered.count("-") >= 3:
            flags.append(f"Link contains an unusually long, hyphen-heavy domain (common spoofing trick): {url}")
    return flags


def analyze_keywords(text: str):
    """Flags urgency language, credential/payment requests, and generic greetings."""
    flags = []
    lowered = text.lower()

    matched_urgency = [phrase for phrase in URGENCY_PHRASES if phrase in lowered]
    if matched_urgency:
        flags.append(
            "Uses urgency/pressure language to rush the reader into acting without thinking: "
            + ", ".join(f'"{m}"' for m in matched_urgency)
        )

    matched_credentials = [phrase for phrase in CREDENTIAL_REQUEST_PHRASES if phrase in lowered]
    if matched_credentials:
        flags.append(
            "Requests sensitive information that a legitimate organization would never ask for by email/message: "
            + ", ".join(f'"{m}"' for m in matched_credentials)
        )

    matched_greeting = [phrase for phrase in GENERIC_GREETINGS if phrase in lowered]
    if matched_greeting:
        flags.append(
            "Uses a generic greeting instead of your actual name, suggesting a mass-sent message: "
            + ", ".join(f'"{m}"' for m in matched_greeting)
        )

    return flags


def analyze_message(text: str):
    """Runs all checks and returns a list of red flags found in the message."""
    urls = find_urls(text)
    flags = []
    flags.extend(analyze_keywords(text))
    flags.extend(analyze_links(urls))

    if not urls:
        flags.append("Note: no links were found in this message — review the wording alone for red flags.")

    return flags


def verdict(flags):
    """Gives a simple risk verdict based on how many real red flags were found."""
    # The "no links found" note doesn't count as a red flag on its own.
    real_flags = [f for f in flags if not f.startswith("Note:")]
    count = len(real_flags)
    if count == 0:
        return "LOW RISK", "No common phishing indicators were detected, but always stay cautious."
    elif count <= 2:
        return "MEDIUM RISK", "Some suspicious signals were found. Verify the sender through a separate, trusted channel before acting."
    else:
        return "HIGH RISK", "Multiple strong phishing indicators were found. Do not click any links, reply, or share information."


# ---------------------------------------------------------------------------
# Sample messages for demonstration
# ---------------------------------------------------------------------------

SAMPLE_MESSAGES = {
    "1": (
        "Suspicious bank alert",
        """Dear Customer,

We have detected unusual activity on your account. Your account will be suspended
within 24 hours unless you verify your identity immediately.

Click here to confirm your account: http://192.168.45.12/secure-login

Failure to respond will result in permanent account closure.

Regards,
Security Team"""
    ),
    "2": (
        "Fake prize / gift card scam",
        """Dear Valued Customer,

Congratulations! You have been selected to receive a $500 gift card.
Act now, this offer expires today! Click the link below and enter your
credit card number to cover a small shipping fee.

https://bit.ly/claim-your-prize-now

Thank you,
Rewards Team"""
    ),
    "3": (
        "Legitimate-looking newsletter",
        """Hi Fatima,

Here's your weekly newsletter from DecodeLabs. This week we cover three new
articles on network security fundamentals.

Read more at: https://decodelabs.com/blog/network-security-basics

See you next week,
The DecodeLabs Team"""
    ),
}


def print_divider():
    print("-" * 60)


def run_analysis(label: str, text: str):
    print_divider()
    print(f"MESSAGE: {label}")
    print_divider()
    print(text.strip())
    print_divider()

    flags = analyze_message(text)
    risk, explanation = verdict(flags)

    print(f"\nRED FLAGS FOUND ({len([f for f in flags if not f.startswith('Note:')])}):")
    if not flags:
        print("  None found.")
    else:
        for i, flag in enumerate(flags, start=1):
            print(f"  {i}. {flag}")

    print(f"\nVERDICT: {risk}")
    print(f"WHY: {explanation}\n")


def main():
    print("=" * 60)
    print("   PROJECT 3: PHISHING AWARENESS ANALYSIS")
    print("=" * 60)

    while True:
        print("\nMenu:")
        print("1. Analyze a sample message (built-in examples)")
        print("2. Analyze your own message")
        print("3. Exit")

        choice = input("Choose an option (1-3): ").strip()

        if choice == "1":
            print("\nAvailable samples:")
            for key, (label, _) in SAMPLE_MESSAGES.items():
                print(f"  {key}. {label}")
            pick = input("Pick a sample number: ").strip()
            if pick in SAMPLE_MESSAGES:
                label, text = SAMPLE_MESSAGES[pick]
                run_analysis(label, text)
            else:
                print("Invalid selection.")

        elif choice == "2":
            print("Paste the message text below. Type END on its own line when finished:")
            lines = []
            while True:
                line = input()
                if line.strip() == "END":
                    break
                lines.append(line)
            text = "\n".join(lines)
            if text.strip():
                run_analysis("User-submitted message", text)
            else:
                print("No text entered.")

        elif choice == "3":
            print("Exiting program. Stay safe out there!")
            break

        else:
            print("Invalid choice. Please select a number between 1 and 3.")


if __name__ == "__main__":
    main()
