from __future__ import annotations
import json
from pathlib import Path
import pytest

from json_consistency_repair.streaming import (
    StreamingConfig, StreamingParseError, discover_stream_knowledge, iter_records, repair_stream_file,
)


def write_jsonl(path: Path, rows):
    path.write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in rows) + "\n", encoding="utf-8")


def read_jsonl(path: Path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_stream_second_cycle_uses_newly_revealed_relation(tmp_path):
    rows=[]
    for i in range(10): rows.append({"code":"A","country":"US","x":i+1,"y":2*i+3})
    for i in range(10): rows.append({"code":"B","country":"CA","x":100+i,"y":500+i})
    rows[8]["code"]="a"; rows[9]["code"]="a"; rows[9]["country"]="XX"
    src=tmp_path/"in.jsonl"; out=tmp_path/"out.jsonl"; rep=tmp_path/"report.json"; write_jsonl(src,rows)
    r=repair_stream_file(src,out,rep)
    fixed=read_jsonl(out)
    assert fixed[8]["code"] == "A"
    assert fixed[9]["code"] == "A" and fixed[9]["country"] == "US"
    assert [c["committed_edits"] for c in r.report["cycles"][:2]] == [2,1]
    assert r.report["cycles"][1]["new_relations"]  # relation certified only after pass-1 corrections
    assert r.report["replay"]["inverse_restores_complete_input"] is True


def test_exact_arithmetic_stream_repair(tmp_path):
    rows=[]
    for i in range(20): rows.append({"a":i+2,"b":i+3,"total":2*i+5})
    rows[7]["total"]=999
    src=tmp_path/"x.jsonl"; out=tmp_path/"o.jsonl"; write_jsonl(src,rows)
    r=repair_stream_file(src,out)
    assert read_jsonl(out)[7]["total"] == rows[7]["a"] + rows[7]["b"]
    assert r.final_status == "PASS"


def test_constant_determinant_not_promoted_to_functional_relation(tmp_path):
    rows=[{"constant":"X","target":"A" if i<19 else "B","vary":i} for i in range(20)]
    src=tmp_path/"x.jsonl"; write_jsonl(src,rows)
    k=discover_stream_knowledge(src)
    assert not any(r["kind"]=="functional_stream" and r["determinant"]=="/constant" and r["output"]=="/target" for r in k["relations"])


def test_functional_group_overflow_disables_pair(tmp_path):
    rows=[]
    for i in range(80):
        rows.extend([{"key":f"K{i}","value":f"V{i}","group":"G"+str(i%2)} for _ in range(3)])
    src=tmp_path/"x.jsonl"; write_jsonl(src,rows)
    cfg=StreamingConfig(max_functional_groups=16,max_relation_fields=3,max_tracked_fields=8)
    k=discover_stream_knowledge(src,cfg)
    assert k["bounded_state"]["overflowed_functional_pairs"] > 0
    assert not any(r["kind"]=="functional_stream" and r["determinant"]=="/key" and r["output"]=="/value" for r in k["relations"])


def test_required_missing_is_diagnosed_but_not_invented(tmp_path):
    rows=[{"id":i,"name":"N"+str(i)} for i in range(20)]
    del rows[-1]["name"]
    src=tmp_path/"x.jsonl"; out=tmp_path/"o.jsonl"; write_jsonl(src,rows)
    r=repair_stream_file(src,out)
    assert "name" not in read_jsonl(out)[-1]
    assert r.final_status == "STABLE_WITH_REPORTED_ISSUES"
    assert r.remaining_issues >= 1


def test_top_level_array_streams_with_tiny_chunks(tmp_path):
    rows=[{"id":i,"payload":"x"*(17+(i%5))} for i in range(75)]
    src=tmp_path/"x.json"; src.write_text(json.dumps(rows,ensure_ascii=False),encoding="utf-8")
    got=[e.value for e in iter_records(src,stream_format="array",chunk_bytes=23)]
    assert got == rows
    out=tmp_path/"o.json"; r=repair_stream_file(src,out,config=StreamingConfig(chunk_bytes=19),stream_format="array")
    assert json.loads(out.read_text(encoding="utf-8")) == rows
    assert r.records == len(rows)


def test_nested_object_leaf_paths(tmp_path):
    rows=[]
    for i in range(20): rows.append({"item":{"kind":"A" if i<10 else "B","label":"alpha" if i<10 else "beta"},"n":i})
    rows[4]["item"]["label"]="WRONG"
    src=tmp_path/"x.jsonl"; out=tmp_path/"o.jsonl"; write_jsonl(src,rows)
    r=repair_stream_file(src,out)
    assert read_jsonl(out)[4]["item"]["label"] == "alpha"
    assert r.final_status == "PASS"


def test_malformed_jsonl_fails_with_line_number(tmp_path):
    src=tmp_path/"bad.jsonl"; src.write_text('{"a":1}\n{"b":}\n',encoding="utf-8")
    with pytest.raises(StreamingParseError,match="physical line 2"):
        discover_stream_knowledge(src)


def test_non_object_record_is_rejected_for_inference(tmp_path):
    src=tmp_path/"bad.jsonl"; src.write_text('{"a":1}\n[1,2]\n',encoding="utf-8")
    with pytest.raises(StreamingParseError,match="requires object records"):
        discover_stream_knowledge(src)


def test_tracked_state_is_capped_independent_of_row_count(tmp_path):
    src=tmp_path/"wide.jsonl"
    rows=[]
    for i in range(500):
        rows.append({f"f{j}": i+j for j in range(40)})
    write_jsonl(src,rows)
    cfg=StreamingConfig(max_tracked_fields=9,max_relation_fields=5,max_numeric_fields=4)
    k=discover_stream_knowledge(src,cfg)
    assert k["bounded_state"]["tracked_fields"] <= 9
    assert k["bounded_state"]["relation_fields"] <= 5


def test_triple_idempotence_after_stream_repair(tmp_path):
    rows=[]
    for i in range(30): rows.append({"kind":"A" if i<15 else "B","label":"x" if i<15 else "y","a":i+1,"b":2,"sum":i+3})
    rows[3]["label"]="bad"; rows[7]["sum"]=999
    p0=tmp_path/"p0.jsonl"; write_jsonl(p0,rows)
    prev=p0
    edits=[]
    for n in range(4):
        out=tmp_path/f"p{n+1}.jsonl"
        r=repair_stream_file(prev,out)
        edits.append(r.committed_edits); prev=out
    assert edits[0] >= 2
    assert edits[1:] == [0,0,0]
