"""
Hash Analyzer - Identify potential hashing algorithms and formats.
Author: faypap
License: MIT
"""

import argparse
import os
import sys
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple


class Confidence(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass(frozen=True)
class HashSignature:
    algorithm: str
    confidence: Confidence
    details: str

class HashEngine:
    """Core analysis engine for detecting hash formats."""

    # Explicit prefix patterns mapped to algorithm names and contexts
    PREFIX_MAP: List[Tuple[str, str, str]] = [
        ("$argon2id$", "Argon2id", "PHC standard string format"),
        ("$argon2i$", "Argon2i", "PHC string (side-channel resistant)"),
        ("$2b$", "bcrypt", "bcrypt standard string"),
        ("$2a$", "bcrypt", "bcrypt legacy string"),
        ("$2y$", "bcrypt", "bcrypt PHP variant"),
        ("$6$", "SHA-512 Crypt", "Linux shadow password hash"),
        ("$5$", "SHA-256 Crypt", "Linux shadow password hash"),
        ("$1$", "MD5 Crypt", "Legacy Unix password hash"),
        ("$apr1$", "Apache MD5", "Apache htpasswd format"),
        ("$y$", "yescrypt", "Modern Linux crypt format"),
        ("$P$", "phpass", "WordPress / phpBB hash"),
        ("{SSHA}", "LDAP SSHA", "Salted SHA-1 (Base64)"),
        ("{SHA}", "LDAP SHA", "SHA-1 (Base64)"),
        ("pbkdf2_sha256$", "Django PBKDF2-SHA256", "Django default framework hash"),
    ]

    # Hex length rules mapped to potential candidates (Ordered by popularity)
    HEX_LENGTH_MAP = {
        16: ["MySQL323", "CRC-64"],
        32: ["MD5", "NTLM", "MD4"],
        40: ["SHA-1", "RIPEMD-160"],
        48: ["Tiger-192"],
        56: ["SHA-224", "SHA3-224"],
        64: ["SHA-256", "SHA3-256", "BLAKE2s-256"],
        96: ["SHA-384", "SHA3-384"],
        128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],
    }

    HEX_CHARS = set("0123456789abcdefABCDEF")
    HEX_UPPER = set("0123456789ABCDEF")

    @classmethod
    def analyze(cls, hash_string: str) -> List[HashSignature]:
        """Runs candidate string through the signature detection pipeline."""
        target = hash_string.strip()
        if not target:
            return []

        # 1.Direct Prefix Matching
        prefix_matches = cls._check_prefixes(target)
        if prefix_matches:
            return prefix_matches

        # 2.Structural & Format-Specific Check
        special_matches = cls._check_special_cases(target)
        if special_matches:
            return special_matches

        # 3.Fixed-length Hex Check
        if all(c in cls.HEX_CHARS for c in target):
            return cls._check_hex_lengths(len(target))

        # 4.Fallback checks (e.g. general PHC structure, token indicators)
        return cls._check_fallbacks(target)

    @classmethod
    def _check_prefixes(cls, target: str) -> List[HashSignature]:
        for prefix, name, info in cls.PREFIX_MAP:
            if target.startswith(prefix):
                return [
                    HashSignature(
                        algorithm=name,
                        confidence=Confidence.HIGH,
                        details=f"Matched explicit prefix '{prefix}' ({info})",
                    )
                ]
        return []

    @classmethod
    def _check_special_cases(cls, target: str) -> List[HashSignature]:
        # MySQL5 checking: Starts with '*' followed by 40 hex uppercase chars
        if len(target) == 41 and target.startswith("*"):
            if all(c in cls.HEX_UPPER for c in target[1:]):
                return [
                    HashSignature(
                        algorithm="MySQL5",
                        confidence=Confidence.HIGH,
                        details="Format matches '*<40 UPPERCASE HEX>'",
                    )
                ]

        # NetNTLMv2 challenge response check
        if "::" in target and target.count(":") >= 4:
            parts = target.split(":")
            if len(parts) >= 6 and len(parts[4]) == 32:
                return [
                    HashSignature(
                        algorithm="NetNTLMv2",
                        confidence=Confidence.HIGH,
                        details="Active Directory Challenge-Response structure",
                    )
                ]

        return []

    @classmethod
    def _check_hex_lengths(cls, length: int) -> List[HashSignature]:
        matches = cls.HEX_LENGTH_MAP.get(length, [])
        results = []

        for idx, algo in enumerate(matches):
            conf = Confidence.MEDIUM if idx == 0 else Confidence.LOW
            note = (
                "Primary candidate for this byte-length"
                if idx == 0
                else "Possible candidate based on output size"
            )
            results.append(
                HashSignature(
                    algorithm=algo,
                    confidence=conf,
                    details=f"{length} hex characters — {note}",
                )
            )

        return results

    @classmethod
    def _check_fallbacks(cls, target: str) -> List[HashSignature]:
        # Generic PHC pattern check ($identifier$...)
        if target.startswith("$") and target.count("$") >= 2:
            algo_id = target.split("$")[1]
            if algo_id.isalnum():
                return [
                    HashSignature(
                        algorithm=f"Generic PHC ({algo_id})",
                        confidence=Confidence.LOW,
                        details="Generic PHC layout detected, specific signature unlisted",
                    )
                ]

        # Non-hash indicators
        if target.startswith("eyJ"):
            return [
                HashSignature(
                    algorithm="JWT (JSON Web Token)",
                    confidence=Confidence.LOW,
                    details="Header starts with Base64 JSON indicator 'eyJ' (Not a hash)",
                )
            ]

        return []

# Terminal Formatting & File Utilities

def display_results(hash_str: str, results: List[HashSignature], max_display: int):
    """Outputs structured table for a single target string."""
    print(f"\n[+] Analysis Results for: {hash_str.strip()}")
    print("=" * 75)
    print(f"{'ALGORITHM':<22} | {'CONFIDENCE':<10} | {'REASON / DETAILS'}")
    print("-" * 75)

    if not results:
        print(f"{'UNKNOWN':<22} | {'N/A':<10} | No matching signatures found.")
    else:
        for item in results[:max_display]:
            print(f"{item.algorithm:<22} | {item.confidence.value:<10} | {item.details}")

    print("=" * 75)


def process_file(file_path: str, max_display: int):
    """Reads hashes line by line from a text file and runs analysis."""
    if not os.path.exists(file_path):
        print(f"\n[-] Error: File not found at '{file_path}'\n")
        sys.exit(1)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"\n[-] Error reading file: {e}\n")
        sys.exit(1)

    if not lines:
        print(f"\n[-] Warning: File '{file_path}' is empty or contains only blank lines.\n")
        return

    print(f"\n[🚀] Processing {len(lines)} hash(es) from file: {file_path}")
    for idx, line in enumerate(lines, 1):
        print(f"\n--- [Entry {idx}/{len(lines)}] ---")
        matches = HashEngine.analyze(line)
        display_results(line, matches, max_display)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Identify unknown hashes using structural and length signatures."
    )
    
    # Mutually exclusive group: provide either a single hash or a file path
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("hash", nargs="?", help="A single hash string to analyze")
    group.add_argument(
        "-f",
        "--file",
        type=str,
        help="Path to a text file containing one hash per line",
    )

    parser.add_argument(
        "-n",
        "--top",
        type=int,
        default=5,
        help="Limit number of candidates printed per hash (default: 5)",
    )

    args = parser.parse_args()

    # Mode 1:File Batch Processing
    if args.file:
        process_file(args.file, args.top)
    
    # Mode 2:Single Hash Processing
    elif args.hash:
        matches = HashEngine.analyze(args.hash)
        if not matches:
            print("\n[-] Unknown Hash: No signatures matched the provided string.\n")
            sys.exit(1)
        display_results(args.hash, matches, args.top)
        print()


if __name__ == "__main__":
    main()