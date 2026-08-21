from json_consistency_repair.engine import repair_object, RepairConfig


def cfg(**kw):
    base=dict(min_support=4,min_group_support=2,relation_confidence=.80,scoped_relation_confidence=.90,
              arithmetic_confidence=.80,temporal_confidence=.80,sequential_confidence=.75,
              required_key_confidence=.90,shape_confidence=.70,enum_confidence=.85,
              reference_confidence=.80,id_uniqueness_confidence=.80)
    base.update(kw)
    return RepairConfig(**base)


def test_schema_missing_required_key_is_detected_but_not_invented():
    rows=[{"id":i,"name":f"n{i}","status":"ok"} for i in range(10)]
    del rows[7]["name"]
    data={"rows":rows}
    out,r=repair_object(data,cfg(required_key_confidence=.90))
    assert "name" not in out["rows"][7]
    assert any(i["code"]=="missing_required_key" and i["path"]=="/rows/7/name" for i in r.report["remaining_issues"])
    assert any(x["kind"]=="required_key" and x["output"]=="name" for x in r.report["relations"])


def test_enum_case_variant_is_canonicalized():
    vals=["OPEN","OPEN","CLOSED","CLOSED","OPEN","CLOSED","OPEN","CLOSED","OPEN","open"]
    data={"rows":[{"id":i,"state":v} for i,v in enumerate(vals)]}
    out,r=repair_object(data,cfg(enum_confidence=.90,enum_normalization_confidence=.75))
    assert out["rows"][9]["state"]=="OPEN"
    assert any(c["analyzer"]=="enum_domain" for c in r.report["committed_edits"])


def test_enum_unknown_value_is_reported_without_guessing():
    vals=["OPEN","OPEN","CLOSED","CLOSED","OPEN","CLOSED","OPEN","CLOSED","OPEN","BROKEN"]
    data={"rows":[{"id":i,"state":v} for i,v in enumerate(vals)]}
    out,r=repair_object(data,cfg(enum_confidence=.90))
    assert out==data
    assert any(i["code"]=="enum_domain_outlier" for i in r.report["remaining_issues"])


def test_foreign_reference_case_variant_repaired():
    users=[{"id":f"U{i}","name":f"user{i}"} for i in range(10)]
    orders=[{"id":i,"user_id":f"U{i}"} for i in range(9)] + [{"id":9,"user_id":"u9"}]
    data={"users":users,"orders":orders}
    out,r=repair_object(data,cfg(reference_confidence=.90,id_uniqueness_confidence=1.0))
    assert out["orders"][9]["user_id"]=="U9"
    assert any(x["kind"]=="foreign_reference" for x in r.report["relations"])
    assert any(c["analyzer"]=="identifier_reference" for c in r.report["committed_edits"])


def test_dangling_reference_reported_without_guessing():
    users=[{"id":f"U{i}"} for i in range(10)]
    orders=[{"id":i,"user_id":f"U{i}"} for i in range(9)] + [{"id":9,"user_id":"NOPE"}]
    data={"users":users,"orders":orders}
    out,r=repair_object(data,cfg(reference_confidence=.90,id_uniqueness_confidence=1.0))
    assert out==data
    assert any(i["code"]=="dangling_reference" for i in r.report["remaining_issues"])


def test_near_unique_identifier_duplicates_are_detected_not_repaired():
    users=[{"id":i,"name":f"u{i}"} for i in range(9)] + [{"id":8,"name":"duplicate"}]
    data={"users":users}
    out,r=repair_object(data,cfg(id_uniqueness_confidence=.90))
    assert out==data
    issues=[i for i in r.report["remaining_issues"] if i["code"]=="duplicate_identifier"]
    assert len(issues)==2


def test_cross_family_consensus_can_anchor_arithmetic_direction():
    rows=[]
    for i in range(10):
        plan="A" if i<5 else "B"
        subtotal,tax,total=(10,2,12) if plan=="A" else (20,4,24)
        if i==4: total=999
        o={"plan":plan,"subtotal":subtotal,"tax":tax,"total":total}
        if i%2: o={"total":total,"tax":tax,"subtotal":subtotal,"plan":plan}
        rows.append(o)
    out,r=repair_object({"rows":rows},cfg(arithmetic_direction_confidence=.95))
    assert out["rows"][4]["total"]==12
    accepted=[a for cyc in r.report["cycles"] for a in cyc["accepted"] if a["candidate"]["path"]=="/rows/4/total"]
    assert accepted
    assert set(accepted[0]["families"]) >= {"exact_arithmetic","functional_relation"}


def test_two_independent_equations_anchor_direction_without_key_order():
    rows=[]
    for i in range(10):
        a,b=10+i,2
        c,d=20+i,10
        # both a+b and c-d equal 12+i
        total=a+b
        c=total+d
        if i==5: total=999
        o={"a":a,"b":b,"c":c,"d":d,"total":total}
        if i%2: o={"total":total,"d":d,"c":c,"b":b,"a":a}
        rows.append(o)
    out,r=repair_object({"rows":rows},cfg(arithmetic_direction_confidence=.95,max_numeric_fields=8))
    assert out["rows"][5]["total"]==17
    edits=[c for c in r.report["committed_edits"] if c["path"]=="/rows/5/total"]
    assert edits
    assert edits[0]["metadata"]["direction_source"]=="multi_equation_consensus"
    assert len(edits[0]["metadata"]["agreeing_formulas"])>=2


def test_constraint_graph_contains_schema_enum_and_reference_edges():
    users=[{"id":f"U{i}","role":"ADMIN" if i%2 else "USER"} for i in range(10)]
    orders=[{"id":i,"user_id":f"U{i}"} for i in range(10)]
    out,r=repair_object({"users":users,"orders":orders},cfg(id_uniqueness_confidence=1.0,reference_confidence=1.0))
    kinds={e["kind"] for e in r.report["constraint_graph"]["edges"]}
    assert "required_key" in kinds
    assert "enum_domain" in kinds
    assert "foreign_reference" in kinds
