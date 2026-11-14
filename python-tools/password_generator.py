#!/usr/bin/env python3
"""
Cybersecurity Toolkit - Password Generator

Generates secure random passwords or passphrases using Python's `secrets`
module (cryptographically secure). Nothing is saved or sent anywhere.

Examples:
    python password_generator.py                       one 16-char password
    python password_generator.py -l 24 -n 5            five 24-char passwords
    python password_generator.py --no-symbols          letters and digits only
    python password_generator.py --no-ambiguous        skip 0 O o 1 l I
    python password_generator.py --passphrase          6 random words
    python password_generator.py --passphrase --words 8 --wordlist words.txt
"""

import argparse
import math
import secrets
import string
import sys
from pathlib import Path

AMBIGUOUS = set("0Oo1lI|`'\"")

# Small built-in list for convenience. For stronger passphrases use --wordlist
# with a bigger list (e.g. the EFF large wordlist with 7776 words).
BUILTIN_WORDS = """
able acid acorn actor adapt agent alarm album alert alley amber anchor angle
apple april arch arena armor arrow atlas attic aunt avid badge baker banjo
barn basil beach beam bench bison blade blank blast bloom boat bolt bonus
brave bread brick bridge brook brush cabin cable cactus camel candy canoe
canyon cargo carpet cedar chair chalk charm chess chief cider cliff clock
cloud clover coast cobra comet coral cotton crane crisp crown cubic daisy
dance delta denim desert diary diner dolphin dragon drift eagle earth echo
elbow ember engine fabric falcon fancy feather fern ferry fiber field flame
flint flute forest fossil frost garden gentle ginger glacier globe grain
grape gravel grove guitar hammer harbor hazel heron hill honey horizon
island ivory jacket jungle kettle kitten ladder lagoon lantern lemon lilac
linen lizard lunar magnet maple marble meadow melon mirror mist monkey
mosaic motor nectar noble north oasis ocean olive onion orbit otter oxygen
paddle panda paper pearl pepper piano pilot planet plum polar pond poppy
quartz quiet rabbit radar rain raven river robin rocket saddle sailor salmon
sand scarf shadow silver sketch slate smoke snow solar spice spring stone
storm sugar summer swan table tiger timber torch tower trail tulip tunnel
turtle umbrella valley velvet violin walnut water willow window winter
wolf yacht yellow zebra zephyr
""".split()


def load_words(path: Path | None) -> list[str]:
    if path is None:
        return sorted(set(BUILTIN_WORDS))
    words = {w.strip().lower() for w in path.read_text().splitlines()
             if w.strip() and not w.startswith("#")}
    return sorted(words)


def make_password(length: int, use_symbols: bool, no_ambiguous: bool):
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.<>?/~")
    if no_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
    alphabet = "".join(pools)

    # Guarantee at least one character from every pool, then fill the rest
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars), length * math.log2(len(alphabet))


def make_passphrase(words: list[str], count: int, sep: str, capitalize: bool):
    picked = [secrets.choice(words) for _ in range(count)]
    if capitalize:
        picked = [w.capitalize() for w in picked]
    return sep.join(picked), count * math.log2(len(words))


def rating(bits: float) -> str:
    if bits < 40:
        return "weak"
    if bits < 60:
        return "fair"
    if bits < 80:
        return "strong"
    return "very strong"


def main() -> int:
    p = argparse.ArgumentParser(description="Secure password generator.")
    p.add_argument("-l", "--length", type=int, default=16,
                   help="Password length (default 16)")
    p.add_argument("-n", "--count", type=int, default=1,
                   help="How many to generate (default 1)")
    p.add_argument("--no-symbols", action="store_true", help="No symbols")
    p.add_argument("--no-ambiguous", action="store_true",
                   help="Avoid look-alike characters (0 O 1 l I)")
    p.add_argument("--passphrase", action="store_true",
                   help="Generate a word-based passphrase")
    p.add_argument("--words", type=int, default=6,
                   help="Words in passphrase (default 6)")
    p.add_argument("--separator", default="-", help="Passphrase separator")
    p.add_argument("--capitalize", action="store_true",
                   help="Capitalize each passphrase word")
    p.add_argument("--wordlist", type=Path, help="Custom word list file")
    args = p.parse_args()

    if not 1 <= args.count <= 100:
        print("Error: --count must be between 1 and 100.", file=sys.stderr)
        return 1

    if args.passphrase:
        try:
            words = load_words(args.wordlist)
        except OSError as e:
            print(f"Error: cannot read word list: {e}", file=sys.stderr)
            return 1
        if len(words) < 100:
            print("Error: word list needs at least 100 words.", file=sys.stderr)
            return 1
        if not 3 <= args.words <= 20:
            print("Error: --words must be between 3 and 20.", file=sys.stderr)
            return 1
        gen = lambda: make_passphrase(words, args.words, args.separator,
                                      args.capitalize)
        info = f"{args.words} words from a list of {len(words)}"
    else:
        if not 8 <= args.length <= 256:
            print("Error: --length must be between 8 and 256.", file=sys.stderr)
            return 1
        gen = lambda: make_password(args.length, not args.no_symbols,
                                    args.no_ambiguous)
        info = f"{args.length} characters"

    print("=" * 32)
    print("      PASSWORD GENERATOR")
    print("=" * 32)
    bits = 0.0
    for _ in range(args.count):
        value, bits = gen()
        print(value)
    print(f"\n[*] {info}, ~{bits:.0f} bits of entropy ({rating(bits)})")
    if args.passphrase and args.wordlist is None and bits < 60:
        print("[!] The built-in word list is small. Use --words 10 or a "
              "bigger --wordlist (e.g. EFF large list) for more strength.")
    print("[*] Store it in a password manager. Never reuse passwords.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
