"""Unit tests for OutputParser."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.output_parser import OutputParser


def test_extract_flags_basic():
    """Test basic flag extraction."""
    parser = OutputParser()

    # Test various flag formats
    text = """
    [INFO] Starting scan
    [FLAG] flag{test-flag-123}
    [FLAG] FLAG{another-flag}
    [INFO] More output
    """

    flags = parser.extract_flags(text)
    assert "flag{test-flag-123}" in flags
    assert "FLAG{another-flag}" in flags


def test_extract_flags_htb_format():
    """Test HTB flag format."""
    parser = OutputParser()

    text = "[FLAG] HTB{hackthebox_flag}"
    flags = parser.extract_flags(text)
    assert "HTB{hackthebox_flag}" in flags


def test_extract_flags_hex_format():
    """Test 32-char hex flag format."""
    parser = OutputParser()

    text = "Found user flag: a1b2c3d4e5f6789012345678901234ab"
    flags = parser.extract_flags(text)
    assert "a1b2c3d4e5f6789012345678901234ab" in flags


def test_parse_done_line():
    """Test DONE line parsing."""
    parser = OutputParser()

    line = "[DONE] Flags: 1, Cost: $0.1234, Session: abc123"
    result = parser.parse_done_line(line)

    assert result is not None
    assert result["flags_count"] == 1
    assert result["cost_usd"] == 0.1234
    assert result["session_id"] == "abc123"


def test_parse_done_line_multiple_flags():
    """Test DONE line with multiple flags."""
    parser = OutputParser()

    line = "[DONE] Flags: 3, Cost: $1.5678, Session: xyz789"
    result = parser.parse_done_line(line)

    assert result is not None
    assert result["flags_count"] == 3
    assert result["cost_usd"] == 1.5678
    assert result["session_id"] == "xyz789"


def test_parse_done_line_invalid():
    """Test DONE line parsing with invalid format."""
    parser = OutputParser()

    line = "[INFO] Some other line"
    result = parser.parse_done_line(line)

    assert result is None


def test_parse_output_complete():
    """Test complete output parsing."""
    parser = OutputParser()

    lines = [
        "[INFO] Target: http://example.com",
        "[INFO] Starting agent...",
        "[TOOL] bash: nmap -sV example.com",
        "[MESSAGE] Scanning ports...",
        "[FLAG] flag{example_flag}",
        "[DONE] Flags: 1, Cost: $0.0234, Session: test123",
    ]

    result = parser.parse_output(lines)

    assert "flag{example_flag}" in result["flags"]
    assert result["cost"] == 0.0234
    assert result["session_id"] == "test123"
    assert not result["has_error"]
    assert result["error_msg"] is None


def test_parse_output_with_error():
    """Test output parsing with errors."""
    parser = OutputParser()

    lines = [
        "[INFO] Starting...",
        "[ERROR] Connection failed",
        "[ERROR] Timeout occurred",
    ]

    result = parser.parse_output(lines)

    assert result["has_error"]
    assert "Connection failed" in result["error_msg"]
    assert "Timeout occurred" in result["error_msg"]


def test_flag_deduplication():
    """Test that duplicate flags are removed."""
    parser = OutputParser()

    text = """
    [FLAG] flag{duplicate}
    [INFO] Found it again
    [FLAG] flag{duplicate}
    """

    flags = parser.extract_flags(text)
    # Should only have one instance
    assert flags.count("flag{duplicate}") == 1


def test_validate_strict_pattern_valid():
    """Test strict pattern validation with valid flags."""
    parser = OutputParser()

    # Valid: FLAG{32+ alphanumeric chars}
    assert parser.validate_strict_pattern("FLAG{f9a0cb1e9aa6749b100a8ad6b75627f6afbd3b1dc5eca6d2b92083fec5949b8d}")
    assert parser.validate_strict_pattern("flag{85c0d8275e284577be2b319bdcbf872d}")

    # Valid: UUID format with hyphens
    assert parser.validate_strict_pattern("flag{85c0d827-5e28-4577-be2b-319bdcbf872d}")


def test_validate_strict_pattern_invalid_format():
    """Test strict pattern validation with wrong format."""
    parser = OutputParser()

    # Wrong prefix
    assert not parser.validate_strict_pattern("HTB{85c0d8275e284577be2b319bdcbf872d}")
    assert not parser.validate_strict_pattern("private{self}")
    assert not parser.validate_strict_pattern("CTF{85c0d8275e284577be2b319bdcbf872d}")


def test_validate_strict_pattern_too_short():
    """Test strict pattern validation with short content."""
    parser = OutputParser()

    # Less than 32 characters
    assert not parser.validate_strict_pattern("flag{short}")
    assert not parser.validate_strict_pattern("FLAG{1234567890123456789012345678901}")  # 31 chars
    assert not parser.validate_strict_pattern("flag{self}")

    # Exactly 32 characters should pass
    assert parser.validate_strict_pattern("flag{12345678901234567890123456789012}")  # 32 chars


def test_validate_strict_pattern_case_insensitive():
    """Test that pattern matching is case-insensitive."""
    parser = OutputParser()

    # Different cases should all be valid
    assert parser.validate_strict_pattern("FLAG{85c0d8275e284577be2b319bdcbf872d}")
    assert parser.validate_strict_pattern("flag{85c0d8275e284577be2b319bdcbf872d}")
    assert parser.validate_strict_pattern("Flag{85c0d8275e284577be2b319bdcbf872d}")
    assert parser.validate_strict_pattern("FlaG{85c0d8275e284577be2b319bdcbf872d}")


def test_filter_strict_flags():
    """Test filtering flags by strict pattern."""
    parser = OutputParser()

    flags = [
        "flag{85c0d8275e284577be2b319bdcbf872d}",  # Valid
        "FLAG{a1b2c3d4e5f6789012345678901234ab}",  # Valid
        "HTB{hackthebox_flag}",                     # Wrong prefix
        "flag{short}",                              # Too short
        "private{self}",                            # Wrong prefix and short
        "flag{85c0d827-5e28-4577-be2b-319bdcbf872d}",  # Valid (UUID with hyphens)
    ]

    strict = parser.filter_strict_flags(flags)
    assert len(strict) == 3
    assert "flag{85c0d8275e284577be2b319bdcbf872d}" in strict
    assert "FLAG{a1b2c3d4e5f6789012345678901234ab}" in strict
    assert "flag{85c0d827-5e28-4577-be2b-319bdcbf872d}" in strict


def test_filter_strict_flags_empty():
    """Test filtering with no valid flags."""
    parser = OutputParser()

    flags = [
        "HTB{hackthebox}",
        "private{self}",
        "flag{short}",
    ]

    strict = parser.filter_strict_flags(flags)
    assert len(strict) == 0


if __name__ == "__main__":
    # Run tests manually
    print("Running OutputParser tests...")

    tests = [
        ("test_extract_flags_basic", test_extract_flags_basic),
        ("test_extract_flags_htb_format", test_extract_flags_htb_format),
        ("test_extract_flags_hex_format", test_extract_flags_hex_format),
        ("test_parse_done_line", test_parse_done_line),
        ("test_parse_done_line_multiple_flags", test_parse_done_line_multiple_flags),
        ("test_parse_done_line_invalid", test_parse_done_line_invalid),
        ("test_parse_output_complete", test_parse_output_complete),
        ("test_parse_output_with_error", test_parse_output_with_error),
        ("test_flag_deduplication", test_flag_deduplication),
        ("test_validate_strict_pattern_valid", test_validate_strict_pattern_valid),
        ("test_validate_strict_pattern_invalid_format", test_validate_strict_pattern_invalid_format),
        ("test_validate_strict_pattern_too_short", test_validate_strict_pattern_too_short),
        ("test_validate_strict_pattern_case_insensitive", test_validate_strict_pattern_case_insensitive),
        ("test_filter_strict_flags", test_filter_strict_flags),
        ("test_filter_strict_flags_empty", test_filter_strict_flags_empty),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            print(f"  ✓ {name}")
            passed += 1
        except AssertionError as e:
            print(f"  ✗ {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ {name}: Unexpected error: {e}")
            failed += 1

    print(f"\n{passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
