"""Bank transaction file validation (SR-5, SR-7).

Banks drop CSV files into S3 under incoming/<tenant>/<YYYYMMDD>/<name>.csv.
The worker that processes a file only trusts the tenant from the S3 key if
it matches the tenant of the IAM role / token that delivered it, and rejects
anything that looks like a full card number, because we only need last-4
(data minimization: we cannot leak what we never store)."""
import csv
import io
import re

KEY_PATTERN = re.compile(r"^incoming/(?P<tenant>[a-z0-9-]{3,32})/(?P<date>\d{8})/[A-Za-z0-9_.-]{1,100}\.csv$")
EXPECTED_COLUMNS = ["account_id", "transaction_id", "merchant", "amount_cents", "posted_on", "card_last4"]
PAN_PATTERN = re.compile(r"(?<!\d)\d{13,19}(?!\d)")


class RejectedFile(ValueError):
    pass


def validate_key(key: str, caller_tenant: str) -> str:
    match = KEY_PATTERN.match(key)
    if not match or ".." in key:
        raise RejectedFile("object key does not match the expected layout")
    if match.group("tenant") != caller_tenant:
        raise RejectedFile("object key belongs to a different tenant")
    return match.group("tenant")


def parse_file(content: str, max_bytes: int) -> list[dict]:
    if len(content.encode()) > max_bytes:
        raise RejectedFile("file too large")
    reader = csv.DictReader(io.StringIO(content))
    if reader.fieldnames != EXPECTED_COLUMNS:
        raise RejectedFile("unexpected columns")
    rows = []
    for line_no, row in enumerate(reader, start=2):
        if any(PAN_PATTERN.search(value or "") for value in row.values()):
            # Never echo the value back: the error message would itself leak the PAN.
            raise RejectedFile(f"line {line_no}: possible full card number; send last 4 digits only")
        if not re.fullmatch(r"\d{4}", row["card_last4"] or ""):
            raise RejectedFile(f"line {line_no}: card_last4 must be exactly 4 digits")
        if not re.fullmatch(r"-?\d{1,12}", row["amount_cents"] or ""):
            raise RejectedFile(f"line {line_no}: amount_cents must be an integer")
        rows.append(row)
    return rows
