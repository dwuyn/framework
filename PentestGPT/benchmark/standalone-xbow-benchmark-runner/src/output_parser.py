"""Output parser for PentestGPT raw mode output."""

import re


class OutputParser:
    """Parses PentestGPT raw output to extract flags, cost, and session info."""

    FLAG_PATTERNS = [
        r"flag\{[^\}]+\}",
        r"FLAG\{[^\}]+\}",
        r"HTB\{[^\}]+\}",
        r"CTF\{[^\}]+\}",
        r"\b[a-f0-9]{32}\b"  # 32-char hex for HTB-style flags
    ]

    # Strict pattern for --pattern-flag mode
    STRICT_FLAG_PATTERN = re.compile(
        r'^(flag|FLAG)\{([a-zA-Z0-9\-]+)\}$',
        re.IGNORECASE
    )

    def parse_output(self, lines: list[str]) -> dict:
        """
        Extract metadata from output lines.

        Args:
            lines: List of output lines from PentestGPT

        Returns:
            dict with 'flags', 'cost', 'session_id', 'has_error', 'error_msg'
        """
        flags = []
        cost = 0.0
        session_id = ""
        flags_count = None
        has_error = False
        error_msg = None

        # Join all lines for flag extraction
        full_text = "\n".join(lines)
        flags = self.extract_flags(full_text)

        # Parse individual lines for structured output
        for line in lines:
            # Parse [DONE] line
            if "[DONE]" in line:
                done_data = self.parse_done_line(line)
                if done_data:
                    cost = done_data.get("cost_usd", 0.0)
                    session_id = done_data.get("session_id", "")
                    flags_count = done_data.get("flags_count")

            # Check for errors
            if "[ERROR]" in line:
                has_error = True
                # Extract error message (everything after [ERROR])
                error_part = line.split("[ERROR]", 1)
                if len(error_part) > 1:
                    if error_msg is None:
                        error_msg = error_part[1].strip()
                    else:
                        error_msg += " | " + error_part[1].strip()

        return {
            "flags": flags,
            "flags_count": flags_count,
            "cost": cost,
            "session_id": session_id,
            "has_error": has_error,
            "error_msg": error_msg
        }

    def extract_flags(self, text: str) -> list[str]:
        """
        Find all flag patterns in text.

        Args:
            text: Text to search

        Returns:
            List of unique flags found
        """
        flags = set()

        for pattern in self.FLAG_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.update(matches)

        return list(flags)

    def validate_strict_pattern(self, flag: str) -> bool:
        """
        Validate if flag matches strict pattern requirements.

        Requirements:
        - Format: FLAG{...} or flag{...} (case-insensitive)
        - Content inside braces: at least 32 characters
        - Content: alphanumeric + hyphens (hex-like, supports UUIDs)

        Args:
            flag: Flag string to validate

        Returns:
            True if flag matches strict pattern, False otherwise

        Examples:
            >>> validate_strict_pattern("FLAG{f9a0cb1e9aa6749b100a8ad6b75627f6afbd3b1dc5eca6d2b92083fec5949b8d}")
            True
            >>> validate_strict_pattern("flag{85c0d827-5e28-4577-be2b-319bdcbf872d}")
            True
            >>> validate_strict_pattern("private{self}")
            False
        """
        match = self.STRICT_FLAG_PATTERN.match(flag)
        if not match:
            return False

        # Extract content inside braces (group 2)
        content = match.group(2)

        # Check minimum length
        if len(content) < 32:
            return False

        return True

    def filter_strict_flags(self, flags: list[str]) -> list[str]:
        """
        Filter flags to only include those matching strict pattern.

        Args:
            flags: List of flag strings

        Returns:
            List of flags that match strict pattern
        """
        return [f for f in flags if self.validate_strict_pattern(f)]

    def parse_done_line(self, line: str) -> dict | None:
        """
        Parse [DONE] line to extract metadata.

        Expected format: [DONE] Flags: X, Cost: $Y, Session: Z

        Args:
            line: Line containing [DONE] marker

        Returns:
            dict with 'flags_count', 'cost_usd', 'session_id' or None
        """
        # Try to match the expected format
        match = re.search(
            r"\[DONE\]\s+Flags:\s*(\d+),\s*Cost:\s*\$([0-9.]+),\s*Session:\s*(.+)",
            line
        )

        if match:
            return {
                "flags_count": int(match.group(1)),
                "cost_usd": float(match.group(2)),
                "session_id": match.group(3).strip()
            }

        return None
