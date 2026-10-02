"""SR-5 and SR-7: bank file validation."""
import pytest

from app.ingest import RejectedFile, parse_file, validate_key

HEADER = "account_id,transaction_id,merchant,amount_cents,posted_on,card_last4\n"


def test_good_key():
    assert validate_key("incoming/bank-a/20260930/batch_01.csv", "bank-a") == "bank-a"


@pytest.mark.parametrize("key", [
    "incoming/bank-b/20260930/batch_01.csv",          # another tenant's prefix
    "incoming/bank-a/../bank-b/20260930/x.csv",       # traversal
    "incoming/bank-a/20260930/batch.csv.exe",         # wrong extension
    "/etc/passwd",
])
def test_bad_keys(key):
    with pytest.raises(RejectedFile):
        validate_key(key, "bank-a")


def test_good_file():
    assert len(parse_file(HEADER + "acct_a_001,t9,Cafe,450,2026-09-30,4242\n", 10_000)) == 1


def test_full_pan_rejected_and_not_echoed():
    with pytest.raises(RejectedFile) as err:
        parse_file(HEADER + "acct_a_001,t9,Cafe 4111111111111111,450,2026-09-30,4242\n", 10_000)
    assert "4111111111111111" not in str(err.value)


def test_unexpected_columns_rejected():
    with pytest.raises(RejectedFile):
        parse_file("account_id,ssn\nacct_a_001,123-45-6789\n", 10_000)


def test_oversize_rejected():
    with pytest.raises(RejectedFile):
        parse_file(HEADER + "x" * 2000, 1000)
