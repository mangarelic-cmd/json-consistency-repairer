from __future__ import annotations
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import random
from json_consistency_repair.engine import RepairConfig
from json_consistency_repair.bundle import repair_bundle, bundle_digest

rnd=random.Random(4004)

def cfg(**kw):
    base=dict(min_support=4,min_group_support=2,relation_confidence=.80,scoped_relation_confidence=.90,
              arithmetic_confidence=.80,temporal_confidence=.80,sequential_confidence=.75,
              required_key_confidence=.90,shape_confidence=.70,enum_confidence=.90,
              enum_normalization_confidence=.75,reference_confidence=.90,id_uniqueness_confidence=.90)
    base.update(kw); return RepairConfig(**base)

counts={}
def hit(k): counts[k]=counts.get(k,0)+1

# 200 cross-document canonical repairs across varying document names/array names.
for t in range(200):
    n=20; bad=rnd.randrange(n); prefix=f"U{t}_"
    docs={
      f"catalog/{t}.json":{"users":[{"id":f"{prefix}{i}","name":f"n{i}"} for i in range(n)]},
      f"events/{t}.json":{"orders":[{"id":100000+t*n+i,"user_id":f"{prefix}{i}"} for i in range(n)]},
    }
    docs[f"events/{t}.json"]["orders"][bad]["user_id"]=f"{prefix}{bad}".lower()
    before=bundle_digest(docs)
    out,r=repair_bundle(docs,cfg())
    assert out[f"events/{t}.json"]["orders"][bad]["user_id"]==f"{prefix}{bad}"
    assert r.input_digest==before and r.report["replay"]["inverse_restores_input"] is True
    hit("cross_reference_repair")

# 150 dangling references: diagnose but never guess.
for t in range(150):
    n=20; bad=rnd.randrange(n); prefix=f"D{t}_"
    docs={
      "users.json":{"users":[{"id":f"{prefix}{i}"} for i in range(n)]},
      "orders.json":{"orders":[{"id":1000+i,"user_id":f"{prefix}{i}"} for i in range(n)]},
    }
    docs["orders.json"]["orders"][bad]["user_id"]="NO_SUCH_GLOBAL_ID"
    out,r=repair_bundle(docs,cfg())
    assert out==docs
    assert any(i["code"]=="cross_document_dangling_reference" for i in r.report["remaining_issues"])
    hit("dangling_abstain")

# 100 ambiguous registries: equal overlap must never pick by lexical filename ordering.
for t in range(100):
    ids=[{"id":f"X{t}_{i}"} for i in range(20)]
    refs={"rows":[{"id":3000+i,"ref_id":f"X{t}_{i}"} for i in range(20)]}
    docs={"left.json":{"left":ids},"right.json":{"right":ids},"refs.json":refs}
    out,r=repair_bundle(docs,cfg(reference_confidence=1.0))
    assert out==docs
    assert any(i["code"]=="ambiguous_reference_target" for i in r.report["remaining_issues"])
    assert not r.report["cross_document_relations"]
    hit("ambiguous_registry_abstain")

# 100 bundles with a local repair and a cross-document repair in the same semantic transaction.
for t in range(100):
    n=20; bad=rnd.randrange(n); prefix=f"T{t}_"
    docs={
      "users.json":{"users":[{"id":f"{prefix}{i}"} for i in range(n)]},
      "orders.json":{"orders":[{"id":4000+i,"user_id":f"{prefix}{i}"} for i in range(n)]},
      "states.json":{"rows":[{"id":i,"state":"READY" if i%2==0 else "DONE"} for i in range(n)]},
    }
    docs["orders.json"]["orders"][bad]["user_id"]=docs["orders.json"]["orders"][bad]["user_id"].lower()
    enum_bad=2*rnd.randrange(n//2)
    docs["states.json"]["rows"][enum_bad]["state"]="ready"
    out,r=repair_bundle(docs,cfg())
    assert out["orders.json"]["orders"][bad]["user_id"]==f"{prefix}{bad}"
    assert out["states.json"]["rows"][enum_bad]["state"]=="READY"
    assert any(x["scope"]=="local" for x in r.report["committed_patch_set"])
    assert any(x["scope"]=="cross_document" for x in r.report["committed_patch_set"])
    assert r.report["transaction"]["inverse_restores_bundle"] is True
    hit("local_plus_cross_transaction")

# 50 repaired bundles, each replayed three times at zero edits.
for t in range(50):
    n=20; bad=rnd.randrange(n); prefix=f"I{t}_"
    docs={"users.json":{"users":[{"id":f"{prefix}{i}"} for i in range(n)]},
          "orders.json":{"orders":[{"id":5000+i,"user_id":f"{prefix}{i}"} for i in range(n)]}}
    docs["orders.json"]["orders"][bad]["user_id"]=docs["orders.json"]["orders"][bad]["user_id"].lower()
    out,r=repair_bundle(docs,cfg())
    cur=out
    for _ in range(3):
        nxt,rr=repair_bundle(cur,cfg())
        assert nxt==cur and rr.committed_edits==0 and rr.report["replay"]["inverse_restores_input"] is True
        cur=nxt
    hit("bundle_idempotence3")

# 50 target registries are revealed only after a local exact sequence correction.
# The bundle analyzer therefore consumes information produced by a preceding local correction.
for t in range(50):
    n=20; bad=10
    users=[{"id":i,"name":f"u{i}"} for i in range(n)]
    users[bad]["id"]=999999+t
    orders=[{"order_id":7000+i,"user_id":i} for i in range(n)]
    docs={"users.json":{"users":users},"orders.json":{"orders":orders}}
    out,r=repair_bundle(docs,cfg(reference_confidence=1.0,sequential_confidence=.75))
    assert out["users.json"]["users"][bad]["id"]==bad
    assert any(x["kind"]=="foreign_reference_cross_document" for x in r.report["cross_document_relations"])
    assert any(x["scope"]=="local" and x["document"]=="users.json" for x in r.report["committed_patch_set"])
    hit("relation_revealed_after_local_correction")

print(counts)
print('TOTAL',sum(counts.values()),'PASS')
