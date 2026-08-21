import json
import pytest
from json_consistency_repair.io import loads_strict, conservative_syntax_repair, DuplicateKeyError
from json_consistency_repair.models import digest


def test_duplicate_keys_rejected():
    with pytest.raises(DuplicateKeyError):
        loads_strict('{"a":1,"a":2}')


def test_unique_trailing_comma_repair():
    value,ops=conservative_syntax_repair('{"a":1,}')
    assert value=={"a":1}
    assert ops and ops[0]["operation"]=="remove_trailing_commas"


def test_canonical_digest_ignores_object_key_order():
    assert digest({"a":1,"b":2})==digest({"b":2,"a":1})
