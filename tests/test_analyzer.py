"""
Unit tests for HashEngine and File Utilities in hash_analyzer.py.
Run with: pytest
"""

import pytest
from hash_analyzer import Confidence, HashEngine, process_file, display_results

# Core Engine Tests: Prefixes & Hashes
def test_bcrypt_prefix_recognition():
    """Verify standard bcrypt ($2b$) is matched with HIGH confidence."""
    sample = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G"
    results = HashEngine.analyze(sample)

    assert len(results) > 0
    assert results[0].algorithm == "bcrypt"
    assert results[0].confidence == Confidence.HIGH


def test_argon2id_prefix_recognition():
    """Verify Argon2id standard PHC string prefix is recognized."""
    sample = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaA"
    results = HashEngine.analyze(sample)

    assert any(r.algorithm == "Argon2id" for r in results)
    assert results[0].confidence == Confidence.HIGH


def test_linux_shadow_sha512_prefix():
    """Verify Linux shadow file SHA-512 ($6$) format is recognized."""
    sample = "$6$rounds=10000$salt$hashedpasswordhere"
    results = HashEngine.analyze(sample)

    assert results[0].algorithm == "SHA-512 Crypt"
    assert results[0].confidence == Confidence.HIGH


def test_django_pbkdf2_prefix():
    """Verify Django default password hash prefix."""
    sample = "pbkdf2_sha256$260000$salt$hash"
    results = HashEngine.analyze(sample)

    assert results[0].algorithm == "Django PBKDF2-SHA256"

# Core Engine Tests: Special Formats

def test_mysql5_uppercase_format():
    """Verify MySQL5 format (* + 40 UPPERCASE hex chars) matches."""
    sample = "*23AE809DDACAF96AF0FD78ED04B6A265E05AA257"
    results = HashEngine.analyze(sample)

    assert results[0].algorithm == "MySQL5"
    assert results[0].confidence == Confidence.HIGH


def test_mysql5_rejects_lowercase():
    """Verify MySQL5 format rejects lowercase hex characters."""
    sample = "*23ae809ddacaf96af0fd78ed04b6a265e05aa257"
    results = HashEngine.analyze(sample)

    if results:
        assert results[0].algorithm != "MySQL5"


def test_netntlmv2_format():
    """Verify NetNTLMv2 challenge-response string structure."""
    sample = "alice::CORP:1122334455667788:" + "a" * 32 + ":" + "b" * 64
    results = HashEngine.analyze(sample)

    assert results[0].algorithm == "NetNTLMv2"
    assert results[0].confidence == Confidence.HIGH

# Core Engine Tests: Hex Length Matching

def test_md5_length_match():
    """Verify 32 hex characters default to MD5 with MEDIUM confidence."""
    sample = "5f4dcc3b5aa765d61d8327deb882cf99"
    results = HashEngine.analyze(sample)

    assert results[0].algorithm == "MD5"
    assert results[0].confidence == Confidence.MEDIUM
    
    algo_names = [r.algorithm for r in results]
    assert "NTLM" in algo_names


def test_sha256_length_match():
    """Verify 64 hex characters default to SHA-256."""
    sample = "a" * 64
    results = HashEngine.analyze(sample)

    assert results[0].algorithm == "SHA-256"
    assert results[0].confidence == Confidence.MEDIUM

# Fallbacks & Edge Cases

def test_empty_and_whitespace_input():
    """Verify empty or space-only input returns empty result list."""
    assert HashEngine.analyze("") == []
    assert HashEngine.analyze("   \n\t") == []


def test_input_trimming():
    """Verify whitespace is trimmed before evaluation."""
    sample = "   5f4dcc3b5aa765d61d8327deb882cf99 \n"
    results = HashEngine.analyze(sample)

    assert len(results) > 0
    assert results[0].algorithm == "MD5"


def test_jwt_indicator():
    """Verify strings starting with base64 'eyJ' report as JWT."""
    sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig"
    results = HashEngine.analyze(sample)

    assert "JWT" in results[0].algorithm
    assert results[0].confidence == Confidence.LOW

# New Feature Tests: File Processing (-f / --file)

def test_process_file_valid_hashes(tmp_path, capsys):
    """Test reading multiple valid hashes from a temporary file."""
    # Create a temp file with sample hashes
    test_file = tmp_path / "sample_hashes.txt"
    test_file.write_text(
        "5f4dcc3b5aa765d61d8327deb882cf99\n"
        "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G\n"
        "*23AE809DDACAF96AF0FD78ED04B6A265E05AA257\n"
    )

    process_file(str(test_file), max_display=5)

    captured = capsys.readouterr().out
    assert "Processing 3 hash(es) from file" in captured
    assert "MD5" in captured
    assert "bcrypt" in captured
    assert "MySQL5" in captured


def test_process_file_nonexistent_path():
    """Verify system exits gracefully when a missing file path is passed."""
    with pytest.raises(SystemExit) as exc_info:
        process_file("non_existent_file_path.txt", max_display=5)

    assert exc_info.value.code == 1


def test_process_file_empty_file(tmp_path, capsys):
    """Verify empty files output a warning without throwing exceptions."""
    empty_file = tmp_path / "empty.txt"
    empty_file.write_text("   \n\n  \n")

    process_file(str(empty_file), max_display=5)

    captured = capsys.readouterr().out
    assert "Warning: File" in captured
    assert "is empty" in captured

# Parametrized Prefix Registration Check

@pytest.mark.parametrize("prefix,algorithm,info", HashEngine.PREFIX_MAP)
def test_all_registered_prefixes(prefix: str, algorithm: str, info: str):
    """Dynamically tests every registered prefix in HashEngine.PREFIX_MAP."""
    sample = prefix + "dummy_payload_data_string"
    results = HashEngine.analyze(sample)

    assert len(results) > 0, f"Failed to match registered prefix: {prefix}"
    assert results[0].algorithm == algorithm
    assert results[0].confidence == Confidence.HIGH