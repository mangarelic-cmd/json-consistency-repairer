from __future__ import annotations
import json
from pathlib import Path
from json_consistency_repair import RepairConfig, repair_object, parse_dsl


def main():
    counts={}; false=0
    def batch(name,fn):
        nonlocal false
        ok=0
        for i in range(100):
            good,mut=fn(i); ok+=int(good); false+=int(mut)
        counts[name]=ok
    batch('inclusive_bounds',lambda i:(repair_object({'x':-i-1},RepairConfig(json_schema={'type':'object','properties':{'x':{'minimum':0}}},max_cycles=4,enable_final_certification=False))[0]['x']==0,False))
    def multiple(i):
        v=3 if i%2 else 3.2
        out,_=repair_object({'x':v},RepairConfig(json_schema={'type':'object','properties':{'x':{'multipleOf':2}}},max_cycles=4,enable_final_certification=False))
        if i%2:return out['x']==v,out['x']!=v
        return out['x']==4,False
    batch('multipleof_tie_abstention',multiple)
    def bob(i):
        inp={'x':5,'status':'bad'}; schema={'type':'object','properties':{'x':{'minimum':10,'maximum':2},'status':{'const':'ok'}}}
        out,_=repair_object(inp,RepairConfig(json_schema=schema,max_cycles=3,enable_final_certification=False));return out==inp,out!=inp
    batch('bounds_of_bounds_block',bob)
    rules=parse_dsl('scope /rows\nminimum score 0\nmaximum score 100\n')
    batch('dsl_boundary',lambda i:(repair_object({'rows':[{'score':-1-i}]},RepairConfig(constraint_rules=rules,max_cycles=4,enable_final_certification=False))[0]['rows'][0]['score']==0,False))
    def dep(i):
        schema={'type':'object','properties':{'card':{},'billing':{'default':f'B{i}'}},'dependentRequired':{'card':['billing']}}
        out,_=repair_object({'card':'x'},RepairConfig(json_schema=schema,max_cycles=4,enable_final_certification=False));return out.get('billing')==f'B{i}',False
    batch('dependent_default',dep)
    def firewall(i):
        inp=[{'x':5}]; schema={'type':'array','items':{'type':'object','properties':{'x':{'maximum':10}}}}; rules=({'kind':'const','array_path':'','field':'x','value':20+i,'rule_id':f'r{i}'},)
        out,_=repair_object(inp,RepairConfig(json_schema=schema,constraint_rules=rules,record_carrier_mode=True,max_cycles=3,enable_final_certification=False));return out==inp,out!=inp
    batch('boundary_firewall',firewall)
    payload={'contract':'json-consistency-repair.pass025-benchmark.v1','version':'0.25.0','decisions':sum(counts.values()),'expected_decisions':600,'counts':counts,'false_mutations':false,'all_checks_pass':sum(counts.values())==600 and false==0}
    text=json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n'
    Path(__file__).with_name('PASS025_BENCHMARK.json').write_text(text,encoding='utf-8')
    print(text,end='')

if __name__=='__main__': main()
