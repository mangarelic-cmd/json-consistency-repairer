from __future__ import annotations

import json
from pathlib import Path
import pytest

from json_consistency_repair import RepairConfig, StreamingConfig, SecurityLimits, SecurityLimitError
from json_consistency_repair.engine import repair_file, repair_object
from json_consistency_repair.bundle import repair_bundle_dir
from json_consistency_repair.io import DuplicateKeyError, loads_strict, dump_file
from json_consistency_repair.streaming import StreamingParseError, discover_stream_knowledge, iter_records, repair_stream_file


def lim(**kw):
    base=SecurityLimits()
    return SecurityLimits(**{**base.__dict__, **kw})


def test_duplicate_keys_rejected_single():
    with pytest.raises(DuplicateKeyError):
        loads_strict('{"a":1,"a":2}')


def test_non_finite_numbers_rejected_single():
    for raw in ['{"x":NaN}','{"x":Infinity}','{"x":-Infinity}','{"x":1e999}']:
        with pytest.raises(ValueError): loads_strict(raw)


def test_number_token_length_is_bounded():
    with pytest.raises(SecurityLimitError, match="integer token") as e:
        loads_strict('{"x":123456789}', lim(max_number_chars=5))
    assert e.value.code == "max_number_chars"


def test_escaped_unpaired_surrogate_is_rejected():
    with pytest.raises(SecurityLimitError) as e:
        loads_strict('{"x":"\\ud800"}')
    assert e.value.code == "invalid_unicode_scalar"


def test_depth_is_rejected_before_recursive_decoder():
    raw='['*300 + '0' + ']'*300
    with pytest.raises(SecurityLimitError) as e:
        loads_strict(raw, lim(max_depth=24))
    assert e.value.code == "max_depth" and e.value.observed == 25


def test_node_budget_rejected_iteratively():
    raw=json.dumps(list(range(40)))
    with pytest.raises(SecurityLimitError) as e:
        loads_strict(raw, lim(max_nodes=20, max_array_items=100))
    assert e.value.code == "max_nodes"


def test_string_and_key_byte_budgets():
    with pytest.raises(SecurityLimitError) as e1:
        loads_strict(json.dumps({"x":"é"*20}), lim(max_string_bytes=10))
    assert e1.value.code == "max_string_bytes"
    with pytest.raises(SecurityLimitError) as e2:
        loads_strict(json.dumps({"abcdefghij":1}), lim(max_key_bytes=4))
    assert e2.value.code == "max_key_bytes"


def test_object_and_array_width_budgets():
    with pytest.raises(SecurityLimitError) as e1:
        loads_strict(json.dumps({str(i):i for i in range(8)}), lim(max_object_keys=4))
    assert e1.value.code == "max_object_keys"
    with pytest.raises(SecurityLimitError) as e2:
        loads_strict(json.dumps(list(range(8))), lim(max_array_items=4))
    assert e2.value.code == "max_array_items"


def test_file_byte_limit_fails_before_output_is_touched(tmp_path):
    src=tmp_path/'in.json'; out=tmp_path/'out.json'; out.write_text('SENTINEL',encoding='utf-8')
    src.write_text(json.dumps({"payload":"x"*200}),encoding='utf-8')
    cfg=RepairConfig(security_limits=lim(max_document_bytes=50))
    with pytest.raises(SecurityLimitError) as e: repair_file(src,out,config=cfg)
    assert e.value.code == "max_document_bytes"
    assert out.read_text(encoding='utf-8') == 'SENTINEL'


def test_syntax_repair_cannot_bypass_security_limit(tmp_path):
    src=tmp_path/'in.json'; src.write_text('{"a":'+('['*40)+'0'+(']'*40)+',}',encoding='utf-8')
    cfg=RepairConfig(security_limits=lim(max_depth=12), syntax_repair=True)
    with pytest.raises(SecurityLimitError): repair_file(src,config=cfg)


def test_direct_python_object_is_validated_before_engine_recursion():
    v=0
    for _ in range(50): v=[v]
    with pytest.raises(SecurityLimitError) as e:
        repair_object(v, RepairConfig(security_limits=lim(max_depth=10)))
    assert e.value.code == 'max_depth'


def test_stream_jsonl_duplicate_keys_rejected(tmp_path):
    src=tmp_path/'x.jsonl'; src.write_text('{"a":1,"a":2}\n',encoding='utf-8')
    with pytest.raises(StreamingParseError,match='duplicate object key'):
        discover_stream_knowledge(src)


def test_stream_array_duplicate_keys_rejected(tmp_path):
    src=tmp_path/'x.json'; src.write_text('[{"a":1,"a":2}]',encoding='utf-8')
    with pytest.raises(StreamingParseError,match='duplicate object key'):
        list(iter_records(src,stream_format='array'))


def test_stream_non_finite_rejected(tmp_path):
    src=tmp_path/'x.jsonl'; src.write_text('{"x":NaN}\n',encoding='utf-8')
    with pytest.raises(StreamingParseError,match='non-finite'):
        discover_stream_knowledge(src)


def test_stream_jsonl_record_byte_limit_and_no_publish(tmp_path):
    src=tmp_path/'x.jsonl'; out=tmp_path/'out.jsonl'; out.write_text('SENTINEL\n',encoding='utf-8')
    src.write_text(json.dumps({"x":"a"*200})+'\n',encoding='utf-8')
    cfg=StreamingConfig(security_limits=lim(max_record_bytes=64))
    with pytest.raises(SecurityLimitError) as e:
        repair_stream_file(src,out,config=cfg)
    assert e.value.code == 'max_record_bytes'
    assert out.read_text(encoding='utf-8') == 'SENTINEL\n'


def test_stream_array_record_byte_limit(tmp_path):
    src=tmp_path/'x.json'; src.write_text(json.dumps([{"x":"é"*100}]),encoding='utf-8')
    limits=lim(max_record_bytes=80)
    with pytest.raises(SecurityLimitError) as e:
        list(iter_records(src,stream_format='array',chunk_bytes=17,security_limits=limits))
    assert e.value.code == 'max_record_bytes'


def test_stream_record_node_and_depth_limits(tmp_path):
    src=tmp_path/'x.jsonl'; src.write_text(json.dumps({"x":list(range(50))})+'\n',encoding='utf-8')
    with pytest.raises(SecurityLimitError) as e1:
        discover_stream_knowledge(src, StreamingConfig(security_limits=lim(max_record_nodes=20,max_array_items=100)))
    assert e1.value.code == 'max_nodes'
    deep={"x":0}; cur=deep
    for _ in range(20): cur["x"]={"x":0}; cur=cur["x"]
    src.write_text(json.dumps(deep)+'\n',encoding='utf-8')
    with pytest.raises(SecurityLimitError) as e2:
        discover_stream_knowledge(src, StreamingConfig(security_limits=lim(max_depth=8)))
    assert e2.value.code == 'max_depth'


def test_bundle_document_count_and_total_bytes_are_bounded(tmp_path):
    src=tmp_path/'bundle'; src.mkdir()
    for i in range(3): (src/f'{i}.json').write_text('{"x":1}',encoding='utf-8')
    cfg=RepairConfig(security_limits=lim(max_bundle_documents=2))
    with pytest.raises(SecurityLimitError) as e: repair_bundle_dir(src,config=cfg)
    assert e.value.code == 'max_bundle_documents'
    cfg2=RepairConfig(security_limits=lim(max_bundle_documents=10,max_bundle_bytes=10))
    with pytest.raises(SecurityLimitError) as e2: repair_bundle_dir(src,config=cfg2)
    assert e2.value.code == 'max_bundle_bytes'


def test_bundle_symlink_is_rejected(tmp_path):
    src=tmp_path/'bundle'; src.mkdir(); outside=tmp_path/'outside.json'; outside.write_text('{"x":1}',encoding='utf-8')
    link=src/'link.json'
    try: link.symlink_to(outside)
    except (OSError,NotImplementedError): pytest.skip('symlinks unavailable')
    with pytest.raises(SecurityLimitError) as e: repair_bundle_dir(src)
    assert e.value.code == 'bundle_symlink'


def test_bundle_output_cannot_be_inside_input(tmp_path):
    src=tmp_path/'bundle'; src.mkdir(); (src/'a.json').write_text('{"x":1}',encoding='utf-8')
    with pytest.raises(ValueError,match='outside the input directory'):
        repair_bundle_dir(src,src/'out')


def test_atomic_dump_replaces_complete_file(tmp_path):
    out=tmp_path/'x.json'; out.write_text('old',encoding='utf-8')
    dump_file({"new":True},out)
    assert json.loads(out.read_text(encoding='utf-8')) == {"new":True}
    assert not list(tmp_path.glob('.x.json.tmp-*'))


def test_failure_code_is_deterministic_across_retries(tmp_path):
    src=tmp_path/'x.jsonl'; src.write_text('{"x":"'+('a'*200)+'"}\n',encoding='utf-8')
    cfg=StreamingConfig(security_limits=lim(max_record_bytes=32))
    got=[]
    for _ in range(3):
        with pytest.raises(SecurityLimitError) as e: discover_stream_knowledge(src,cfg)
        got.append((e.value.code,e.value.limit))
    assert got == [('max_record_bytes',32)]*3
