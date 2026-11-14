#!/usr/bin/env python3
"""
Cybersecurity Toolkit - Hash Generator

Generate hashes of text or files, and verify file integrity.

Examples:
    python hash_generator.py --text "hello"
    python hash_generator.py --text "hello" --algo md5 sha256
    python hash_generator.py --file setup.iso --algo sha256
    python hash_generator.py --file setup.iso --verify <expected_hash>
    python hash_generator.py                      (interactive mode)
"""

import argparse
import hashlib
import hmac
import sys
from pathlib import Path

ALGORITHMS = ("md5", "sha1", "sha256", "sha384", "sha512", "sha3_256", "blake2b")
CHUNK_SIZE = 1024 * 1024  # 1 MB, so big files do not fill memory


def hash_text(text: str, algo: str) -> str:
    return hashlib.new(algo, text.encode("utf-8")).hexdigest()


def hash_file(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with path.open("rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def guess_algo(digest: str) -> str | None:
    """Guess algorithm from hash length (only a hint, not proof)."""
    return {32: "md5", 40: "sha1", 64: "sha256",
            96: "sha384", 128: "sha512"}.get(len(digest))


def main() -> int:
    parser = argparse.ArgumentParser(description="Hash text or files.")
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--text", help="Text to hash")
    src.add_argument("--file", type=Path, help="File to hash")
    parser.add_argument("--algo", nargs="+", choices=ALGORITHMS,
                        default=["sha256"], help="Algorithm(s), default sha256")
    parser.add_argument("--verify", metavar="HASH",
                        help="Expected hash to compare a file against")
    args = parser.parse_args()

    print("=" * 30)
    print("       HASH GENERATOR")
    print("=" * 30)

    # Interactive mode if nothing was given
    if args.text is None and args.file is None:
        args.text = input("Enter text to hash: ")

    if args.file is not None and not args.file.is_file():
        print(f"Error: file paoa jayni: {args.file}", file=sys.stderr)
        return 1

    # Verify mode
    if args.verify:
        if args.file is None:
            print("Error: --verify shudhu --file er shathe kaj kore.", file=sys.stderr)
            return 1
        expected = args.verify.strip().lower()
        algo = guess_algo(expected) or args.algo[0]
        actual = hash_file(args.file, algo)
        print(f"\nAlgorithm : {algo}\nExpected  : {expected}\nActual    : {actual}")
        if hmac.compare_digest(actual, expected):
            print("\n[OK] Hash match korche, file ta unchanged.")
            return 0
        print("\n[FAIL] Hash match korche na! File change hoyeche ba corrupted.")
        return 2

    # Generate mode
    print()
    for algo in args.algo:
        digest = (hash_file(args.file, algo) if args.file
                  else hash_text(args.text, algo))
        print(f"{algo.upper():<9}: {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
