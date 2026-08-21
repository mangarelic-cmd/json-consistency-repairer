from json_consistency_repair.engine import repair_object, RepairConfig


def cfg(**kw):
    base=dict(min_support=4,min_group_support=2,min_scope_support=3,min_scope_group_support=2,
              relation_confidence=.80,scoped_relation_confidence=.90,arithmetic_confidence=.80,
              temporal_confidence=.80,sequential_confidence=.75)
    base.update(kw)
    return RepairConfig(**base)


def test_exact_multiply_and_inverse_discovery():
    data={"rows":[
        {"a":2,"b":3,"product":6},
        {"a":4,"b":2,"product":8},
        {"a":6,"b":3,"product":18},
        {"a":8,"b":4,"product":999},
        {"a":10,"b":5,"product":50},
    ]}
    out,r=repair_object(data,cfg())
    assert out["rows"][3]["product"]==32
    assert r.report["replay"]["inverse_restores_input"] is True
    # Inverse / relations are discovered, but PASS002 does not mutate from an invertible
    # direction unless directionality is independently anchored.
    assert any(x["kind"]=="exact_arithmetic" and x.get("operator")=="/" for x in r.report["relations"])


def test_temporal_constant_delta_repair():
    data={"events":[
        {"start":"2026-01-01T10:00:00","end":"2026-01-01T11:00:00"},
        {"start":"2026-01-02T10:00:00","end":"2026-01-02T11:00:00"},
        {"start":"2026-01-03T10:00:00","end":"2026-01-03T11:00:00"},
        {"start":"2026-01-04T10:00:00","end":"2026-01-04T15:00:00"},
        {"start":"2026-01-05T10:00:00","end":"2026-01-05T11:00:00"},
    ]}
    out,r=repair_object(data,cfg())
    assert out["events"][3]["end"]=="2026-01-04T11:00:00"
    assert any(x["kind"]=="temporal_delta" for x in r.report["relations"])


def test_sequence_two_sided_repair():
    data={"rows":[
        {"seq":10},{"seq":20},{"seq":30},{"seq":999},{"seq":50},{"seq":60}
    ]}
    out,r=repair_object(data,cfg(min_support=3))
    assert out["rows"][3]["seq"]==40
    assert any(x["kind"]=="sequence_step" for x in r.report["relations"])


def test_scoped_relation_repairs_when_global_relation_is_ambiguous():
    data={"rows":[
        {"region":"NA","plan":"A","currency":"USD"},
        {"region":"NA","plan":"A","currency":"USD"},
        {"region":"NA","plan":"B","currency":"CAD"},
        {"region":"NA","plan":"B","currency":"CAD"},
        {"region":"EU","plan":"A","currency":"EUR"},
        {"region":"EU","plan":"A","currency":"EUR"},
        {"region":"EU","plan":"B","currency":"GBP"},
        {"region":"EU","plan":"B","currency":"WRONG"},
    ]}
    out,r=repair_object(data,cfg(min_scope_support=4,min_scope_group_support=1,scoped_relation_confidence=.75))
    assert out["rows"][7]["currency"]=="GBP"
    assert any(x["kind"]=="scoped_functional" for x in r.report["relations"])


def test_constraint_graph_and_knowledge_ledger_exist():
    data={"rows":[
        {"x":"A","y":"one"},{"x":"A","y":"one"},{"x":"B","y":"two"},
        {"x":"B","y":"two"},{"x":"A","y":"one"},{"x":"B","y":"two"},
    ]}
    out,r=repair_object(data,cfg())
    assert r.report["constraint_graph"]["edges"]
    assert r.report["knowledge_ledger"]["relations"]
    assert r.report["knowledge_ledger"]["newly_certified"]


def test_second_pass_can_expose_new_relation_without_being_rejected_for_more_information():
    # First relation repairs group; subsequent analyses are allowed to expose additional constraints.
    data={"rows":[
        {"id":1,"kind":"A","code":"X","value":10,"double":20},
        {"id":2,"kind":"A","code":"X","value":20,"double":40},
        {"id":3,"kind":"A","code":"X","value":30,"double":60},
        {"id":4,"kind":"A","code":"BAD","value":40,"double":80},
        {"id":5,"kind":"A","code":"X","value":50,"double":100},
        {"id":6,"kind":"A","code":"X","value":60,"double":120},
    ]}
    out,r=repair_object(data,cfg())
    assert out["rows"][3]["code"]=="X"
    assert r.cycles>=2
    assert r.report["replay"]["inverse_restores_input"] is True


def test_subtraction_repair_when_structure_anchors_direction():
    data={"rows":[
        {"a":10,"b":3,"d":7},
        {"a":20,"b":4,"d":16},
        {"a":30,"b":5,"d":25},
        {"a":40,"b":6,"d":999},
        {"a":50,"b":7,"d":43},
    ]}
    out,r=repair_object(data,cfg())
    assert out["rows"][3]["d"]==34
    rel=[x for x in r.report["relations"] if x["kind"]=="exact_arithmetic" and x.get("formula")=="EXACT:d=a-b"]
    assert rel and rel[0]["direction_certified"] is True


def test_arithmetic_abstains_when_equation_direction_is_not_structurally_stable():
    rows=[]
    values=[(10,3,7),(20,4,16),(30,5,25),(40,6,999),(50,7,43)]
    for i,(a,b,d) in enumerate(values):
        # Alternate key order so no field has a stable "inputs before output" witness.
        rows.append({"a":a,"b":b,"d":d} if i%2==0 else {"d":d,"b":b,"a":a})
    data={"rows":rows}
    out,r=repair_object(data,cfg(arithmetic_direction_confidence=.90))
    assert out==data
    assert any(x["kind"]=="exact_arithmetic" and x.get("formula")=="EXACT:d=a-b" for x in r.report["relations"])


def test_missing_sequence_key_reconstructed():
    data={"rows":[{"seq":1},{"seq":2},{"seq":3},{},{"seq":5},{"seq":6}]}
    out,r=repair_object(data,cfg(min_support=3,sequential_confidence=.75))
    assert out["rows"][3]["seq"]==4


def test_missing_temporal_key_reconstructed():
    data={"events":[
        {"start":"2026-02-01T00:00:00","end":"2026-02-01T00:30:00"},
        {"start":"2026-02-02T00:00:00","end":"2026-02-02T00:30:00"},
        {"start":"2026-02-03T00:00:00","end":"2026-02-03T00:30:00"},
        {"start":"2026-02-04T00:00:00"},
        {"start":"2026-02-05T00:00:00","end":"2026-02-05T00:30:00"},
    ]}
    out,r=repair_object(data,cfg())
    assert out["events"][3]["end"]=="2026-02-04T00:30:00"


def test_idempotence_after_repair():
    data={"rows":[
        {"x":"A","y":"one"},{"x":"A","y":"one"},{"x":"B","y":"two"},
        {"x":"B","y":"BAD"},{"x":"A","y":"one"},{"x":"B","y":"two"},
    ]}
    first,r1=repair_object(data,cfg(relation_confidence=.80))
    second,r2=repair_object(first,cfg(relation_confidence=.80))
    assert second==first
    assert r2.committed_edits==0
    assert r2.report["replay"]["inverse_restores_input"] is True


def test_constraint_graph_relation_ids_are_stable_across_idempotent_run():
    data={"rows":[
        {"x":"A","y":"one"},{"x":"A","y":"one"},{"x":"B","y":"two"},
        {"x":"B","y":"two"},{"x":"A","y":"one"},{"x":"B","y":"two"},
    ]}
    out,r1=repair_object(data,cfg())
    out2,r2=repair_object(out,cfg())
    ids1={e["relation_id"] for e in r1.report["constraint_graph"]["edges"]}
    ids2={e["relation_id"] for e in r2.report["constraint_graph"]["edges"]}
    assert ids1==ids2
