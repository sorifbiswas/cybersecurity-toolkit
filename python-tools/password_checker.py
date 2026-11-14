#!/usr/bin/env python3
"""
Cybersecurity Toolkit - Password Strength Checker
Author: sorif biswas

Checks length, character variety, common passwords, simple patterns and
estimates entropy. The password is read with getpass (not shown on screen)
and is never saved or sent anywhere.

Examples:
    python password_checker.py
    python password_checker.py --show        (show typed password)
"""

import argparse
import getpass
import math
import re
import string
import sys

# Small built-in list. For real use, load a bigger list such as a top-10k file.
COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "password", "password1", "qwerty",
    "qwerty123", "abc123", "111111", "123123", "admin", "admin123",
    "letmein", "welcome", "iloveyou", "monkey", "dragon", "football",
    "login", "passw0rd", "1q2w3e4r", "000000", "bangladesh", "india123",
}
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def charset_size(pw: str) -> int:
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"\d", pw):
        size += 10
    if re.search(rf"[{re.escape(string.punctuation)}]", pw):
        size += len(string.punctuation)
    if re.search(r"[^\x00-\x7f]", pw):
        size += 100  # non-ASCII characters
    return size


def entropy_bits(pw: str) -> float:
    """Rough upper-bound estimate: length * log2(charset size)."""
    size = charset_size(pw)
    return len(pw) * math.log2(size) if size else 0.0


def has_sequence(pw: str, n: int = 4) -> bool:
    """Detect runs like abcd, 1234 or qwer (forward or backward)."""
    low = pw.lower()
    sources = [string.ascii_lowercase, string.digits] + KEYBOARD_ROWS
    for src in sources:
        for s in (src, src[::-1]):
            for i in range(len(s) - n + 1):
                if s[i:i + n] in low:
                    return True
    return False


def analyze(pw: str) -> dict:
    issues, tips = [], []
    score = 0
    low = pw.lower()

    # Length
    if len(pw) < 8:
        issues.append("Khub choto (8 character er kom)")
    elif len(pw) < 12:
        score += 1
        tips.append("12+ character use koro")
    elif len(pw) < 16:
        score += 2
    else:
        score += 3

    # Variety
    kinds = sum(bool(re.search(p, pw)) for p in
                (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    score += kinds - 1 if kinds else 0
    if kinds < 3:
        tips.append("Boro/choto hater akkhor, number ar symbol mishao")

    # Weakness checks (these override a high score)
    capped = False
    if low in COMMON_PASSWORDS:
        issues.append("Common password list e ache")
        capped = True
    if re.search(r"(.)\1{2,}", pw):
        issues.append("Ek-i character bar bar repeat hoyeche (aaa, 111)")
        score -= 1
    if has_sequence(pw):
        issues.append("Sequence ache (abcd, 1234, qwer)")
        score -= 1
    if low.isdigit():
        issues.append("Shudhu number")
        score -= 1

    bits = entropy_bits(pw)
    if bits < 40:
        score = min(score, 2)
    if capped:
        score = 0

    score = max(0, min(score, 5))
    labels = ["Very Weak", "Weak", "Weak", "Fair", "Strong", "Very Strong"]
    return {"score": score, "label": labels[score], "bits": round(bits, 1),
            "length": len(pw), "issues": issues, "tips": tips}


def main() -> int:
    parser = argparse.ArgumentParser(description="Password strength checker.")
    parser.add_argument("--show", action="store_true",
                        help="Show password while typing")
    args = parser.parse_args()

    print("=" * 32)
    print("   PASSWORD STRENGTH CHECKER")
    print("=" * 32)

    prompt = "Enter password: "
    pw = input(prompt) if args.show else getpass.getpass(prompt)
    if not pw:
        print("Error: password khali.", file=sys.stderr)
        return 1

    r = analyze(pw)
    bar = "#" * r["score"] + "-" * (5 - r["score"])
    print(f"\nStrength : [{bar}] {r['label']} ({r['score']}/5)")
    print(f"Length   : {r['length']}")
    print(f"Entropy  : ~{r['bits']} bits (estimate)")
    for i in r["issues"]:
        print(f"[-] {i}")
    for t in r["tips"]:
        print(f"[*] {t}")
    if r["score"] >= 4 and not r["issues"]:
        print("[+] Bhalo password!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
