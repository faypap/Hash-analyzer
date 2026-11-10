# Hash Analyzer

[![Tests](https://github.com/faypap/Hash-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/faypap/Hash-analyzer/actions/workflows/tests.yml)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen)

A small command-line tool that looks at an unknown hash string and tells you which algorithm most likely produced it.

Before you can crack or verify a hash with Hashcat or John the Ripper, you have to know what kind of hash it is. Hash Analyzer answers that question from the string's shape alone: its prefix, its structure, its character set and its length. Every guess comes with a confidence level and a short reason, so you can see why it was made.

It is a single Python file with no third-party dependencies.

```console
$ python hash_analyzer.py 5f4dcc3b5aa765d61d8327deb882cf99

[+] Analysis Results for: 5f4dcc3b5aa765d61d8327deb882cf99
===========================================================================
ALGORITHM              | CONFIDENCE | REASON / DETAILS
---------------------------------------------------------------------------
MD5                    | MEDIUM     | 32 hex characters — Primary candidate for this byte-length
NTLM                   | LOW        | 32 hex characters — Possible candidate based on output size
MD4                    | LOW        | 32 hex characters — Possible candidate based on output size
===========================================================================
```

## Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [How detection works](#how-detection-works)
- [Supported formats](#supported-formats)
- [Using it as a library](#using-it-as-a-library)
- [Running the tests](#running-the-tests)
- [Project structure](#project-structure)
- [Limitations](#limitations)
- [Acknowledgements](#acknowledgements)
- [License](#license)

## Features

- Recognises 14 prefixed password-hash formats (bcrypt, Argon2, SHA-crypt, yescrypt, phpass, LDAP, Django and more) with high confidence
- Recognises MySQL5 and NetNTLMv2 by their structure
- Ranks the candidates for raw hex digests of 8 common lengths, from MySQL323 to SHA-512
- Flags JWTs, which are often mistaken for hashes
- Bulk mode: analyse a whole file of hashes, one per line
- Standard library only, so there is nothing to install
- Exit code `1` when a single hash cannot be identified, which makes it usable in shell scripts

## Installation

You need Python 3.9 or newer.

```bash
git clone https://github.com/faypap/Hash-analyzer.git
cd Hash-analyzer
```

That is all. The tool itself has no dependencies; `pytest` is only needed if you want to run the tests.

## Usage

```text
python hash_analyzer.py [-h] [-f FILE] [-n TOP] [hash]
```

| Argument | Meaning |
|----------|---------|
| `hash` | A single hash string to analyse |
| `-f`, `--file FILE` | A text file with one hash per line |
| `-n`, `--top TOP` | Maximum number of candidates shown per hash (default: 5) |

Give either a hash or a file, not both.

### Single hash

```bash
python hash_analyzer.py '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G'
```

```text
[+] Analysis Results for: $2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G
===========================================================================
ALGORITHM              | CONFIDENCE | REASON / DETAILS
---------------------------------------------------------------------------
bcrypt                 | HIGH       | Matched explicit prefix '$2b$' (bcrypt standard string)
===========================================================================
```

> **Quote your hashes.** On Linux and macOS, wrap any hash that contains `$` or `*` in single quotes. Otherwise the shell expands `$2b`, `$6` and so on as variables and the tool receives a mangled string.

### A file of hashes

```bash
python hash_analyzer.py -f hashes.txt
```

Blank lines are skipped, and each remaining line is analysed and printed as its own table. Lines that match nothing are reported as `UNKNOWN`.

### Limiting the output

```bash
python hash_analyzer.py -n 1 5f4dcc3b5aa765d61d8327deb882cf99
```

This shows only the top candidate (`MD5`).

## How detection works

`HashEngine.analyze()` passes the input through four stages and returns as soon as one of them matches.

```text
            Input string (whitespace trimmed)
                         │
                         ▼
   ┌───────────────────────────────────────────┐
   │ 1. Known prefix          $2b$, $argon2id$ │──► HIGH
   └───────────────────────────────────────────┘
                         │ no match
                         ▼
   ┌───────────────────────────────────────────┐
   │ 2. Special structure   MySQL5, NetNTLMv2  │──► HIGH
   └───────────────────────────────────────────┘
                         │ no match
                         ▼
   ┌───────────────────────────────────────────┐
   │ 3. Hex length          32, 40, 64, 128 …  │──► MEDIUM (first) / LOW (rest)
   └───────────────────────────────────────────┘
                         │ not hex
                         ▼
   ┌───────────────────────────────────────────┐
   │ 4. Fallbacks           generic PHC, JWT   │──► LOW
   └───────────────────────────────────────────┘
```

1. **Prefix.** Modern password hashes describe themselves. A string starting with `$2b$` is bcrypt, so a prefix match is reported with high confidence.
2. **Structure.** Some formats have no prefix but a recognisable layout, such as `*` followed by 40 uppercase hex characters for MySQL5.
3. **Hex length.** A raw digest reveals only its length, and several algorithms share each length. The most common one is ranked first with medium confidence and the others follow with low confidence.
4. **Fallbacks.** Unlisted `$id$...` strings are reported as a generic PHC format, and strings starting with `eyJ` are reported as JWTs.

What the confidence levels mean:

| Level | Meaning |
|-------|---------|
| `HIGH` | The format identifies itself through a prefix or a distinctive structure |
| `MEDIUM` | The most common algorithm for this digest length |
| `LOW` | A possible algorithm for this length, or a generic hint |

## Supported formats

### By prefix

| Prefix | Algorithm |
|--------|-----------|
| `$argon2id$` | Argon2id |
| `$argon2i$` | Argon2i |
| `$2b$`, `$2a$`, `$2y$` | bcrypt |
| `$6$` | SHA-512 Crypt |
| `$5$` | SHA-256 Crypt |
| `$1$` | MD5 Crypt |
| `$apr1$` | Apache MD5 |
| `$y$` | yescrypt |
| `$P$` | phpass (WordPress, phpBB) |
| `{SSHA}` | LDAP SSHA |
| `{SHA}` | LDAP SHA |
| `pbkdf2_sha256$` | Django PBKDF2-SHA256 |

### By structure

| Format | Rule |
|--------|------|
| MySQL5 | `*` followed by 40 uppercase hex characters |
| NetNTLMv2 | `user::domain:challenge:hmac:blob`, with a 32-character HMAC field |

### By hex length

| Hex characters | Candidates, most likely first |
|----------------|-------------------------------|
| 16 | MySQL323, CRC-64 |
| 32 | MD5, NTLM, MD4 |
| 40 | SHA-1, RIPEMD-160 |
| 48 | Tiger-192 |
| 56 | SHA-224, SHA3-224 |
| 64 | SHA-256, SHA3-256, BLAKE2s-256 |
| 96 | SHA-384, SHA3-384 |
| 128 | SHA-512, SHA3-512, BLAKE2b-512, Whirlpool |

### Fallbacks

| Input | Reported as |
|-------|-------------|
| `$<id>$...` with an unlisted id | Generic PHC (`<id>`) |
| Starts with `eyJ` | JWT (not a hash) |

## Using it as a library

The engine is separate from the command-line code, so you can import it:

```python
from hash_analyzer import HashEngine

for match in HashEngine.analyze("5f4dcc3b5aa765d61d8327deb882cf99"):
    print(match.algorithm, match.confidence.value, match.details)
```

`analyze()` returns a list of `HashSignature` objects (`algorithm`, `confidence`, `details`), best candidate first. The list is empty when nothing matches.

To support a new format, add a line to `PREFIX_MAP` or `HEX_LENGTH_MAP` in `hash_analyzer.py`. The parametrised test picks up new prefixes automatically.

## Running the tests

```bash
pip install pytest
pytest
```

The suite has 29 tests covering prefix detection, the structural formats, hex length ranking, edge cases such as empty input, and file mode.

## Project structure

```text
Hash-analyzer/
├── hash_analyzer.py        # Detection engine and command-line interface
├── tests/
│   └── test_analyzer.py    # pytest suite
├── pyproject.toml          # Project metadata and pytest configuration
├── LICENSE
└── README.md
```

## Limitations

- The tool identifies hashes. It does not crack them or recover passwords.
- Raw hex digests are ambiguous by nature: MD5, NTLM and MD4 all produce 32 hex characters, and nothing in the string tells them apart. The ranking reflects how common each algorithm is, so treat it as a starting point.
- Only the formats listed above are recognised.

## Acknowledgements

This project was inspired by the [hash-identifier](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/foundations/hash-identifier) project in Carter Perez's Cybersecurity-Projects collection, which I used as a learning reference. Hash Analyzer is my own implementation, with a class-based engine, no external dependencies and a bulk file mode.

## License

Released under the MIT License. See [LICENSE](LICENSE).
