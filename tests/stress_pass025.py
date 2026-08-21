from __future__ import annotations
from json_consistency_repair import RepairConfig, repair_object, parse_dsl


def run():
    counts={k:0 for k in ('numeric_projection','multipleof_conservative','bounds_of_bounds','dsl_boundary','conditional_dependency','boundary_firewall')}
    total=0
    for i in range(100):
        schema={'type':'object','properties':{'x':{'type':'number','minimum':0,'maximum':100}}}
        v=-1-i
        out,res=repair_object({'x':v},RepairConfig(json_schema=schema,max_cycles=4,enable_final_certification=False))
        assert out['x']==0 and not res.remaining_issues
        counts['numeric_projection']+=1; total+=1
    for i in range(100):
        schema={'type':'object','properties':{'x':{'type':'number','multipleOf':2}}}
        value=3.2+2*i if i%2==0 else 3+2*i
        out,res=repair_object({'x':value},RepairConfig(json_schema=schema,max_cycles=4,enable_final_certification=False))
        if i%2==0:
            expected=4+2*i
            assert out['x']==expected
        else:
            assert out['x']==value and any(x.code=='schema_multiple_of_violation' and not x.repairable for x in __import__('json_consistency_repair.schema_bridge',fromlist=['analyze_schema']).analyze_schema(out,RepairConfig(json_schema=schema)).issues)
        counts['multipleof_conservative']+=1; total+=1
    for i in range(100):
        schema={'type':'object','properties':{'x':{'minimum':10+i,'maximum':2},'status':{'const':'ok'}}}
        out,res=repair_object({'x':5,'status':'bad'},RepairConfig(json_schema=schema,max_cycles=3,enable_final_certification=False))
        assert out=={'x':5,'status':'bad'}
        assert res.report['boundary_calculus']['final']['registry']['bounds_of_bounds']['conflict_count']>=1
        counts['bounds_of_bounds']+=1; total+=1
    rules=parse_dsl('scope /rows\nminimum score 0\nmaximum score 100\nmultipleOf score 5\n')
    for i in range(100):
        out,res=repair_object({'rows':[{'score':-(i+1)}]},RepairConfig(constraint_rules=rules,max_cycles=4,enable_final_certification=False))
        assert out['rows'][0]['score']==0
        counts['dsl_boundary']+=1; total+=1
    for i in range(100):
        schema={'type':'object','properties':{'country':{'type':'string'},'postal':{'type':'string','default':f'P{i}'}},
                'if':{'properties':{'country':{'const':'CA'}},'required':['country']},
                'then':{'required':['postal'],'properties':{'postal':{'default':f'P{i}'}}},
                'dependentRequired':{'country':['postal']}}
        out,res=repair_object({'country':'CA'},RepairConfig(json_schema=schema,max_cycles=4,enable_final_certification=False))
        assert out['postal']==f'P{i}'
        counts['conditional_dependency']+=1; total+=1
    for i in range(100):
        schema={'type':'array','items':{'type':'object','properties':{'x':{'maximum':10}}}}
        rules=({'kind':'const','array_path':'','field':'x','value':20+i,'rule_id':f'x{i}'},)
        out,res=repair_object([{'x':5}],RepairConfig(json_schema=schema,constraint_rules=rules,record_carrier_mode=True,max_cycles=3,enable_final_certification=False))
        assert out==[{'x':5}]
        assert any(x.get('rejected',0)>=1 for x in res.report['boundary_calculus']['cycles'])
        counts['boundary_firewall']+=1; total+=1
    assert total==600
    print('PASS025_STRESS',total,counts)

if __name__=='__main__': run()
