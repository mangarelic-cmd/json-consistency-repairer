from json_consistency_repair.engine import repair_object, RepairConfig

def test_exact_sum_second_pass_and_inverse():
    data={"orders":[
      {"id":1,"subtotal":10,"tax":2,"total":12,"country":"CA","currency":"CAD"},
      {"id":2,"subtotal":20,"tax":4,"total":24,"country":"CA","currency":"CAD"},
      {"id":3,"subtotal":30,"tax":6,"total":36,"country":"US","currency":"USD"},
      {"id":4,"subtotal":40,"tax":8,"total":999,"country":"CA","currency":"CAD"},
      {"id":5,"subtotal":50,"tax":10,"total":60,"country":"US","currency":"USD"},
      {"id":6,"subtotal":60,"tax":12,"total":72,"country":"CA","currency":"CAD"},
    ]}
    out,r=repair_object(data,RepairConfig(min_support=4, arithmetic_confidence=.8, relation_confidence=.8))
    assert out["orders"][3]["total"]==48
    assert r.report["replay"]["inverse_restores_input"] is True
    assert r.cycles>=2

def test_functional_missing_repair():
    data={"rows":[
      {"country":"CA","currency":"CAD"}, {"country":"CA","currency":"CAD"},
      {"country":"US","currency":"USD"}, {"country":"US","currency":"USD"},
      {"country":"CA"}, {"country":"US","currency":"USD"}
    ]}
    out,r=repair_object(data,RepairConfig(min_support=4,min_group_support=2,relation_confidence=.9))
    assert out["rows"][4]["currency"]=="CAD"

def test_abstains_on_ambiguous_mapping():
    data={"rows":[
      {"x":"A","y":1},{"x":"A","y":2},{"x":"A","y":1},{"x":"A","y":2},
      {"x":"A","y":9},{"x":"B","y":3}
    ]}
    out,r=repair_object(data,RepairConfig(min_support=4,min_group_support=2,relation_confidence=.95))
    assert out==data
