from __future__ import annotations
from pathlib import Path
import json
from json_consistency_repair.engine import RepairConfig
from json_consistency_repair.bundle import analyze_bundle, bundle_digest, repair_bundle, repair_bundle_dir


def cfg(**kw):
    base=dict(min_support=4,min_group_support=2,relation_confidence=.80,scoped_relation_confidence=.90,
              arithmetic_confidence=.80,temporal_confidence=.80,sequential_confidence=.75,
              required_key_confidence=.90,shape_confidence=.70,enum_confidence=.90,
              reference_confidence=.90,id_uniqueness_confidence=.90)
    base.update(kw); return RepairConfig(**base)


def docs_with_case_error(n=10, bad=9):
    users={"users":[{"id":f"U{i}","name":f"user-{i}"} for i in range(n)]}
    orders={"orders":[{"id":100+i,"user_id":f"U{i}"} for i in range(n)]}
    orders["orders"][bad]["user_id"]=f"u{bad}"
    return {"users.json":users,"orders.json":orders}


def test_cross_document_reference_case_variant_repaired():
    docs=docs_with_case_error()
    out,r=repair_bundle(docs,cfg())
    assert out["orders.json"]["orders"][9]["user_id"]=="U9"
    assert any(x["kind"]=="foreign_reference_cross_document" for x in r.report["cross_document_relations"])
    assert any(x["scope"]=="cross_document" for x in r.report["committed_patch_set"])
    assert r.report["replay"]["inverse_restores_input"] is True


def test_cross_document_dangling_reference_abstains():
    docs=docs_with_case_error(); docs["orders.json"]["orders"][9]["user_id"]="NOPE"
    out,r=repair_bundle(docs,cfg())
    assert out==docs
    assert any(i["code"]=="cross_document_dangling_reference" for i in r.report["remaining_issues"])


def test_ambiguous_cross_document_target_is_reported_not_selected():
    ids=[{"id":f"X{i}"} for i in range(10)]
    refs={"rows":[{"id":100+i,"ref_id":f"X{i}"} for i in range(10)]}
    docs={"a.json":{"a":ids},"b.json":{"b":ids},"refs.json":refs}
    out,r=repair_bundle(docs,cfg(reference_confidence=1.0))
    assert out==docs
    assert any(i["code"]=="ambiguous_reference_target" for i in r.report["remaining_issues"])
    assert not r.report["cross_document_relations"]


def test_global_identity_registry_and_graph_are_document_qualified():
    docs=docs_with_case_error(); out,r=repair_bundle(docs,cfg())
    regs=r.report["identity_registry"]
    assert any(x["document"]=="users.json" and x["array_path"]=="/users" and x["id_field"]=="id" for x in regs)
    edges=r.report["constraint_graph"]["edges"]
    assert any(e["kind"]=="foreign_reference_cross_document" and any("orders.json:/orders#user_id"==i for i in e["inputs"]) and e["output"]=="users.json:/users#id" for e in edges)


def test_bundle_patch_set_replay_restores_global_digest_with_local_and_cross_edits():
    docs=docs_with_case_error()
    # local enum canonicalization in a third document plus the cross-document reference edit
    docs["states.json"]={"rows":[{"id":i,"state":"READY" if i%2==0 else "DONE"} for i in range(10)]}
    docs["states.json"]["rows"][8]["state"]="ready"
    before=bundle_digest(docs)
    out,r=repair_bundle(docs,cfg())
    assert out["states.json"]["rows"][8]["state"]=="READY"
    assert out["orders.json"]["orders"][9]["user_id"]=="U9"
    assert r.committed_edits>=2
    assert r.input_digest==before
    assert r.report["transaction"]["semantic_all_or_none"] is True
    assert r.report["transaction"]["inverse_restores_bundle"] is True


def test_bundle_second_pass_stability_and_cross_document_knowledge_ledger():
    docs=docs_with_case_error()
    out,r=repair_bundle(docs,cfg())
    assert r.cycles>=3  # edit cycle + two explicit stable cycles
    assert r.report["strong_stable"] is True
    assert any(x["scope"]=="cross_document" for x in r.report["knowledge_ledger"]["newly_certified"])
    cur=out
    for _ in range(3):
        nxt,rr=repair_bundle(cur,cfg())
        assert nxt==cur and rr.committed_edits==0 and rr.report["replay"]["inverse_restores_input"] is True
        cur=nxt


def test_bundle_directory_staged_publish_keeps_input_untouched(tmp_path: Path):
    src=tmp_path/"in"; outdir=tmp_path/"out"; src.mkdir()
    docs=docs_with_case_error()
    for name,value in docs.items():
        (src/name).write_text(json.dumps(value),encoding="utf-8")
    original=(src/"orders.json").read_text()
    report=tmp_path/"report.json"
    r=repair_bundle_dir(src,outdir,report,cfg())
    assert (src/"orders.json").read_text()==original
    repaired=json.loads((outdir/"orders.json").read_text())
    assert repaired["orders"][9]["user_id"]=="U9"
    assert r.report["filesystem_commit"]["strategy"]=="staged_directory_publish_with_rollback"
    assert json.loads(report.read_text())["replay"]["inverse_restores_input"] is True


def test_relation_identity_does_not_change_when_only_confidence_changes():
    docs=docs_with_case_error()
    dirty=analyze_bundle(docs,cfg())
    rel_dirty=[x for x in dirty.relations if x["kind"]=="foreign_reference_cross_document"][0]
    out,_=repair_bundle(docs,cfg())
    clean=analyze_bundle(out,cfg())
    rel_clean=[x for x in clean.relations if x["kind"]=="foreign_reference_cross_document"][0]
    assert rel_dirty["confidence"] < rel_clean["confidence"]
    assert rel_dirty["relation_id"] == rel_clean["relation_id"]


def test_public_patch_set_forward_and_inverse_are_all_or_none():
    from json_consistency_repair.bundle import apply_bundle_patch_set
    docs=docs_with_case_error()
    out,r=repair_bundle(docs,cfg())
    replayed=apply_bundle_patch_set(docs,r.report["committed_patch_set"])
    assert replayed==out
    restored=apply_bundle_patch_set(out,r.report["committed_patch_set"],inverse=True)
    assert restored==docs
    tampered={k:json.loads(json.dumps(v)) for k,v in docs.items()}
    tampered["orders.json"]["orders"][9]["user_id"]="OTHER"
    before=json.loads(json.dumps(tampered))
    try:
        apply_bundle_patch_set(tampered,r.report["committed_patch_set"])
    except ValueError:
        pass
    else:
        raise AssertionError("tampered precondition should fail")
    assert tampered==before
