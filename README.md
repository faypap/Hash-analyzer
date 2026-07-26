#  Hash Analyzer

A lightweight, zero-dependency Python utility and testing suite designed to inspect, analyze, and identify unknown hash strings and token formats. 

By evaluating cryptographic prefixes, structural features, character sets, and output lengths, **Hash Analyzer** narrows down candidates and provides confidence-scored results to streamline security audits, forensics, and CTF challenges.

---

##  Table of Contents

- [Overview](#-overview)
- [Architecture & Detection Pipeline](#-architecture--detection-pipeline)
- [Key Features & Engineering Highlights](#-key-features--engineering-highlights)
- [Supported Formats](#-supported-formats)
- [Installation](#-installation)
- [Usage](#-usage)
  - [Single Hash Mode](#1-single-hash-mode)
  - [Bulk File Mode](#2-bulk-file-mode)
- [Running Unit Tests](#-running-unit-tests)
- [Project Structure](#-project-structure)
- [License](#-license)

---

##  Overview

Before initiating hash cracking attempts using tools like Hashcat or John the Ripper, security professionals must determine the target hash type. 

**Hash Analyzer** acts as a static analysis engine that inspects the "shape" of an unknown input to answer: **"Which algorithm produced this digest?"**

Instead of relying on guesswork, it runs target strings through a multi-stage evaluation pipeline and assigns a structured confidence level (`HIGH`, `MEDIUM`, `LOW`) along with context-aware explanations for each candidate.

---

##  Architecture & Detection Pipeline

When an input string is provided to `HashEngine.analyze()`, it traverses four sequential evaluation stages:

```text
               [ Raw Input String ]
                        │
                        ▼
    ┌──────────────────────────────────────┐
    │ 1. Prefix Matching (PHC Standards)   │ ──(Match)──► [ HIGH Confidence ]
    └──────────────────────────────────────┘
                        │ (No Match)
                        ▼
    ┌──────────────────────────────────────┐
    │ 2. Special Structural Layouts        │ ──(Match)──► [ HIGH Confidence ]
    └──────────────────────────────────────┘
                        │ (No Match)
                        ▼
    ┌──────────────────────────────────────┐
    │ 3. Hexadecimal Length Mapping        │ ──(Match)──► [ MEDIUM / LOW Confidence ]
    └──────────────────────────────────────┘
                        │ (No Match)
                        ▼
    ┌──────────────────────────────────────┐
    │ 4. Fallbacks & Token Shape Hints     │ ──(Match)──► [ LOW Confidence ]
    └──────────────────────────────────────┘