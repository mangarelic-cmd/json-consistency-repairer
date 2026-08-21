import json
from pathlib import Path
from json_consistency_repair.constraint_dsl import parse_dsl,ConstraintDSLError
from json_consistency_repair.engine import RepairConfig,repair_object
from json_consistency_repair.schema_bridge import analyze_schema


def cfg(**kw): return RepairConfig(enable_final_certification=False,**kw)

def test_dsl_parses_linear_and_basic_rules():
    r=parse_dsl('''scope /rows\nrequire name default "unknown"\ntype age integer\nenum status ["open","closed"]\nlinear bill: subtotal + tax = total\n''')
    assert [x['kind'] for x in r]==['required','type','enum','linear']
    assert r[-1]['coefficients']=={'subtotal':'1','tax':'1','total':'-1'}

def test_linear_two_equations_identify_corrupted_middle_variable():
    rules=(
      {'kind':'linear','array_path':'/rows','coefficients':{'a':'1','b':'1','c':'-1'},'constant':'0','rule_id':'r1'},
      {'kind':'linear','array_path':'/rows','coefficients':{'c':'1','d':'1','e':'-1'},'constant':'0','rule_id':'r2'},)
    obj={'rows':[{'a':1,'b':2,'c':3,'d':4,'e':7},{'a':2,'b':3,'c':5,'d':4,'e':9},{'a':4,'b':5,'c':9,'d':1,'e':10},{'a':10,'b':2,'c':99,'d':4,'e':16}]}
    repaired,res=repair_object(obj,cfg(constraint_rules=rules))
    assert repaired['rows'][3]['c']==12
    assert res.committed_edits==1

def test_linear_symmetric_single_equation_abstains():
    rules=({'kind':'linear','array_path':'/rows','coefficients':{'a':'1','b':'1','c':'-1'},'constant':'0','rule_id':'r'},)
    obj={'rows':[{'a':1,'b':2,'c':3},{'a':2,'b':3,'c':5},{'a':4,'b':5,'c':9},{'a':10,'b':2,'c':99}]}
    repaired,res=repair_object(obj,cfg(constraint_rules=rules))
    assert repaired==obj and res.committed_edits==0

def test_linear_two_missing_uniquely_jointly_solved():
    rules=(
      {'kind':'linear','array_path':'/rows','coefficients':{'x':'1','y':'1'},'constant':'10','rule_id':'r1'},
      {'kind':'linear','array_path':'/rows','coefficients':{'x':'1','y':'-1'},'constant':'2','rule_id':'r2'},)
    obj={'rows':[{'x':6,'y':4},{'x':6,'y':4},{'x':6,'y':4},{}]}
    repaired,res=repair_object(obj,cfg(constraint_rules=rules))
    assert repaired['rows'][3]=={'x':6,'y':4}
    assert res.committed_edits==2

def test_dsl_required_default_repairs():
    rules=parse_dsl('scope /rows\nrequire country default "CA"')
    obj={'rows':[{'country':'CA'},{'country':'CA'},{'country':'CA'},{}]}
    repaired,res=repair_object(obj,cfg(constraint_rules=rules))
    assert repaired['rows'][3]['country']=='CA'

def test_json_schema_default_and_const_bridge():
    schema={'type':'object','properties':{'kind':{'const':'invoice'},'currency':{'type':'string','default':'CAD'}},'required':['kind','currency']}
    obj={'kind':'wrong'}
    repaired,res=repair_object(obj,cfg(json_schema=schema,schema_source='json_schema'))
    assert repaired=={'kind':'invoice','currency':'CAD'}
    assert res.committed_edits==2

def test_schema_enum_casefold_unique_only():
    schema={'type':'object','properties':{'status':{'enum':['OPEN','CLOSED']}}}
    repaired,res=repair_object({'status':'open'},cfg(json_schema=schema))
    assert repaired['status']=='OPEN'

def test_schema_forbidden_extra_is_diagnostic_not_deleted():
    schema={'type':'object','properties':{'id':{'type':'integer'}},'additionalProperties':False}
    obj={'id':1,'mystery':9}; repaired,res=repair_object(obj,cfg(json_schema=schema))
    assert repaired==obj and res.committed_edits==0
    assert any(i['code']=='schema_additional_property' for i in res.report['terminal_registry'])

def test_dsl_invalid_nonlinear_rejected():
    try: parse_dsl('scope /rows\nlinear nope: a*b = c')
    except (ConstraintDSLError,ValueError): pass
    else: raise AssertionError('nonlinear product must not be silently accepted as linear DSL')

def test_cli_constraints_file(tmp_path):
    from json_consistency_repair.cli import main
    inp=tmp_path/'in.json'; out=tmp_path/'out.json'; rules=tmp_path/'rules.dsl'
    inp.write_text('{"rows":[{"country":"CA"},{"country":"CA"},{"country":"CA"},{}]}')
    rules.write_text('scope /rows\nrequire country default "CA"\n')
    rc=main([str(inp),'-o',str(out),'--constraints',str(rules),'--machine'])
    assert rc==0 and json.loads(out.read_text())['rows'][3]['country']=='CA'

def test_cli_openapi_bridge_with_component_ref(tmp_path):
    from json_consistency_repair.cli import main
    inp=tmp_path/'in.json'; out=tmp_path/'out.json'; api=tmp_path/'openapi.json'
    inp.write_text('{"kind":"bad"}')
    api.write_text(json.dumps({'openapi':'3.1.0','components':{'schemas':{'Kind':{'type':'string'},'Thing':{'type':'object','properties':{'kind':{'const':'ok'}},'required':['kind']}}}}))
    rc=main([str(inp),'-o',str(out),'--openapi',str(api),'--openapi-schema','Thing','--machine'])
    assert rc==0 and json.loads(out.read_text())['kind']=='ok'

def test_cyclic_schema_ref_refused(tmp_path):
    from json_consistency_repair.cli import _load_schema
    from json_consistency_repair.security import SecurityLimits
    p=tmp_path/'s.json'; p.write_text(json.dumps({'$defs':{'A':{'$ref':'#/$defs/A'}},'$ref':'#/$defs/A'}))
    try:_load_schema(str(p),SecurityLimits())
    except ValueError as e: assert 'cyclic' in str(e)
    else: raise AssertionError('cyclic refs must be refused')

def test_linear_inconsistent_system_abstains():
    rules=(
      {'kind':'linear','array_path':'/rows','coefficients':{'x':'1'},'constant':'1','rule_id':'r1'},
      {'kind':'linear','array_path':'/rows','coefficients':{'x':'1'},'constant':'2','rule_id':'r2'},)
    obj={'rows':[{'x':1},{'x':1},{'x':1},{'x':9}]}
    repaired,res=repair_object(obj,cfg(constraint_rules=rules))
    assert repaired==obj and res.committed_edits==0
    terms=[t for t in res.report['terminal_registry'] if t['analyzer']=='linear_exact']
    assert terms

def test_openapi_multiple_schemas_requires_explicit_name(tmp_path):
    from json_consistency_repair.cli import _load_openapi_schema
    from json_consistency_repair.security import SecurityLimits
    p=tmp_path/'o.json'; p.write_text(json.dumps({'openapi':'3.1.0','components':{'schemas':{'A':{'type':'object'},'B':{'type':'object'}}}}))
    try:_load_openapi_schema(str(p),None,SecurityLimits())
    except ValueError as e: assert '--openapi-schema' in str(e)
    else: raise AssertionError('multiple OpenAPI schemas require explicit selection')
