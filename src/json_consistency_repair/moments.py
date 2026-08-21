from __future__ import annotations
from collections import Counter
from copy import deepcopy
from fractions import Fraction
from decimal import Decimal
from typing import Any
import hashlib, json

from .models import AnalysisResult, Issue, Candidate, pointer, digest
from .tree import get, decode_pointer
from .jsonpatch_exact import apply_patch


def _frac(v: Any) -> Fraction | None:
    if isinstance(v, bool) or v is None: return None
    if isinstance(v, int): return Fraction(v,1)
    if isinstance(v, float):
        if v != v or v in (float('inf'),float('-inf')): return None
        return Fraction(str(v))
    if isinstance(v, Decimal): return Fraction(v)
    if isinstance(v, str):
        try: return Fraction(v)
        except Exception: return None
    return None


def _finite_decimal(f: Fraction) -> str | None:
    d=f.denominator
    for p in (2,5):
        while d%p==0: d//=p
    if d!=1: return None
    # exact finite decimal using integer scaling
    d0=f.denominator; twos=fives=0; x=d0
    while x%2==0: x//=2; twos+=1
    while x%5==0: x//=5; fives+=1
    k=max(twos,fives); scale=10**k
    n=f.numerator*(scale//d0)
    sign='-' if n<0 else ''; n=abs(n)
    if k==0: return sign+str(n)
    s=str(n).rjust(k+1,'0'); out=sign+s[:-k]+'.'+s[-k:]
    return out.rstrip('0').rstrip('.')


def _json_num(f: Fraction, examples: list[Any]) -> Any | None:
    s=_finite_decimal(f)
    if s is None: return None
    if f.denominator==1:
        if any(isinstance(x,float) for x in examples): return float(f.numerator)
        return int(f.numerator)
    # JSON has no decimal type; canonical decimal literal is represented by float in-memory.
    # It round-trips through str()/JSON to the same finite decimal for ordinary magnitudes.
    try: return float(s)
    except Exception: return None


def _rid(payload:dict[str,Any])->str:
    base={k:v for k,v in payload.items() if k not in {'confidence','support','relation_id'}}
    return hashlib.sha1(json.dumps(base,sort_keys=True,separators=(',',':'),default=str).encode()).hexdigest()[:20]


def stable_moment_id(rule:dict[str,Any])->str:
    base={k:v for k,v in rule.items() if k not in {'rule_id','confidence','support'}}
    h=hashlib.sha256(json.dumps(base,sort_keys=True,separators=(',',':'),default=str).encode()).hexdigest()[:20]
    return 'moment_'+h


def _resolve(root:Any,path:str)->Any:
    if path in {'',None}: return root
    try: return get(root,path)
    except Exception: return None


def _records(root:Any,array_path:str):
    arr=_resolve(root,array_path)
    if not isinstance(arr,list) or not all(isinstance(x,dict) for x in arr): return None
    return arr


def _items(record:dict[str,Any],field:str):
    x=record.get(field)
    return x if isinstance(x,list) and all(isinstance(y,dict) for y in x) else None


def _weighted_stats(record:dict[str,Any], rule:dict[str,Any])->dict[str,Any]:
    kind=rule.get('kind'); items_field=rule.get('items_field')
    items=_items(record,items_field) if isinstance(items_field,str) else None
    if items is None or not items: return {'status':None,'reason':'insufficient_material'}
    value_field=rule.get('value_field'); weight_field=rule.get('weight_field')
    if kind in {'weighted_mean','weighted_sum','variance'} and not isinstance(value_field,str): return {'status':None,'reason':'invalid_rule'}
    vals=[]; weights=[]
    for item in items:
        if kind in {'weighted_mean','weighted_sum','variance'}:
            x=_frac(item.get(value_field));
            if x is None: return {'status':None,'reason':'insufficient_material'}
            vals.append(x)
        if weight_field is not None:
            if not isinstance(weight_field,str): return {'status':None,'reason':'invalid_rule'}
            w=_frac(item.get(weight_field));
            if w is None: return {'status':None,'reason':'insufficient_material'}
            weights.append(w)
    if weight_field is None: weights=[Fraction(1) for _ in items]
    sw=sum(weights,Fraction(0))
    if sw==0: return {'status':None,'reason':'zero_weight'}
    if kind=='weighted_sum': expected=sum((w*x for w,x in zip(weights,vals)),Fraction(0))
    elif kind=='weighted_mean': expected=sum((w*x for w,x in zip(weights,vals)),Fraction(0))/sw
    elif kind=='variance':
        mean=sum((w*x for w,x in zip(weights,vals)),Fraction(0))/sw
        numer=sum((w*(x-mean)*(x-mean) for w,x in zip(weights,vals)),Fraction(0))
        ddof=int(rule.get('ddof',0) or 0)
        denom=sw-Fraction(ddof)
        if denom<=0: return {'status':None,'reason':'insufficient_degrees_of_freedom'}
        expected=numer/denom
    elif kind=='covariance':
        xf=rule.get('x_field'); yf=rule.get('y_field')
        if not isinstance(xf,str) or not isinstance(yf,str): return {'status':None,'reason':'invalid_rule'}
        xs=[]; ys=[]
        for item in items:
            x=_frac(item.get(xf)); y=_frac(item.get(yf))
            if x is None or y is None: return {'status':None,'reason':'insufficient_material'}
            xs.append(x); ys.append(y)
        mx=sum((w*x for w,x in zip(weights,xs)),Fraction(0))/sw
        my=sum((w*y for w,y in zip(weights,ys)),Fraction(0))/sw
        numer=sum((w*(x-mx)*(y-my) for w,x,y in zip(weights,xs,ys)),Fraction(0))
        ddof=int(rule.get('ddof',0) or 0); denom=sw-Fraction(ddof)
        if denom<=0: return {'status':None,'reason':'insufficient_degrees_of_freedom'}
        expected=numer/denom
    elif kind=='probability_total':
        pf=rule.get('probability_field')
        if not isinstance(pf,str): return {'status':None,'reason':'invalid_rule'}
        ps=[]
        for item in items:
            p=_frac(item.get(pf))
            if p is None: return {'status':None,'reason':'insufficient_material'}
            if p < 0 or p > 1: return {'status':None,'reason':'probability_out_of_range','probability_field':pf}
            ps.append(p)
        expected=sum(ps,Fraction(0))
    elif kind=='uncertainty_variance':
        uf=rule.get('uncertainty_field')
        if not isinstance(uf,str): return {'status':None,'reason':'invalid_rule'}
        us=[]
        for item in items:
            u=_frac(item.get(uf))
            if u is None or u<0: return {'status':None,'reason':'insufficient_material'}
            us.append(u)
        mode=str(rule.get('mode','weighted_mean'))
        numer=sum(((w*u)*(w*u) for w,u in zip(weights,us)),Fraction(0))
        expected=numer/(sw*sw) if mode=='weighted_mean' else numer
    else: return {'status':None,'reason':'unknown_rule_kind'}
    return {'status':True,'expected':expected,'weight_sum':sw,'count':len(items)}


def evaluate_moment_rule(record:dict[str,Any], rule:dict[str,Any])->dict[str,Any]:
    kind=rule.get('kind')
    if kind=='unit_normalize':
        vf=rule.get('value_field'); uf=rule.get('unit_field'); canonical=rule.get('canonical_unit'); conv=rule.get('conversions') or {}
        if not all(isinstance(x,str) for x in (vf,uf,canonical)) or not isinstance(conv,dict): return {'status':None,'reason':'invalid_rule'}
        unit=record.get(uf); value=_frac(record.get(vf))
        if not isinstance(unit,str) or value is None: return {'status':None,'reason':'insufficient_material'}
        if unit==canonical: return {'status':True,'expected_value':value,'expected_unit':canonical}
        spec=conv.get(unit)
        if spec is None: return {'status':None,'reason':'unknown_unit'}
        if isinstance(spec,(int,float,str)): scale=_frac(spec); offset=Fraction(0)
        elif isinstance(spec,dict): scale=_frac(spec.get('scale',1)); offset=_frac(spec.get('offset',0))
        else: scale=None; offset=None
        if scale is None or offset is None: return {'status':None,'reason':'invalid_conversion'}
        return {'status':False,'expected_value':value*scale+offset,'expected_unit':canonical,'source_unit':unit}
    stats=_weighted_stats(record,rule)
    if stats.get('status') is None: return stats
    target=rule.get('target')
    if not isinstance(target,str): return {'status':None,'reason':'invalid_rule'}
    actual=_frac(record.get(target)); expected=stats['expected']
    stats.update({'actual':actual,'target':target,'status': actual==expected if actual is not None else False,'residue':None if actual is None else actual-expected})
    return stats


def analyze_moments(root:Any, config)->AnalysisResult:
    out=AnalysisResult(); document=getattr(config,'moment_document',None)
    rules=[]
    for raw in getattr(config,'moment_rules',()) or ():
        if not isinstance(raw,dict): continue
        if raw.get('document') is not None and (document is None or str(raw.get('document'))!=str(document)): continue
        rr=dict(raw); rr.setdefault('rule_id',stable_moment_id(rr)); rules.append(rr)
    allowed={'weighted_mean','weighted_sum','variance','covariance','probability_total','uncertainty_variance','unit_normalize'}
    for rule in rules:
        kind=rule.get('kind'); rid=rule['rule_id']; ap=str(rule.get('array_path',''))
        arr=_records(root,ap)
        if arr is None and getattr(config,'record_carrier_mode',False) and ap=='' and isinstance(root,list) and len(root)==1 and isinstance(root[0],dict): arr=root
        if kind not in allowed:
            out.issues.append(Issue('moments','moment_rule_invalid',ap,f'Unknown moment rule kind {kind!r}.','error',False,{'rule_id':rid,'constraint_source':'authoritative'})); continue
        if arr is None:
            out.issues.append(Issue('moments','moment_scope_missing',ap,'Moment rule array_path does not resolve to an object array.','error',False,{'rule_id':rid,'constraint_source':'authoritative'})); continue
        rel={'kind':f'{kind}_authoritative','array_path':ap,'inputs':[x for x in (rule.get('items_field'),rule.get('value_field'),rule.get('weight_field'),rule.get('unit_field')) if isinstance(x,str)],
             'output':rule.get('target') or rule.get('value_field'),'confidence':1.0,'support':len(arr),'rule_id':rid,'constraint_source':'authoritative','bridge_kind':'moment_distribution','direction_certified':True,'direction_source':'authoritative_rule'}
        rel['relation_id']=_rid(rel); out.relations.append(rel)
        for i,record in enumerate(arr):
            ev=evaluate_moment_rule(record,rule)
            if ev.get('status') is None and ev.get('reason')=='probability_out_of_range':
                out.issues.append(Issue('moments','probability_out_of_range',pointer(decode_pointer(ap)+[i,rule.get('items_field','')]),'Probability member lies outside [0,1]; aggregate normalization is not allowed to hide it.','error',False,{'rule_id':rid,'constraint_source':'authoritative'}))
                continue
            if ev.get('status') is not False: continue
            if kind=='unit_normalize':
                vf=rule['value_field']; uf=rule['unit_field']; oldv=record.get(vf); oldu=record.get(uf)
                nv=_json_num(ev['expected_value'],[oldv])
                if nv is None:
                    out.issues.append(Issue('moments','nonterminating_unit_conversion',pointer(decode_pointer(ap)+[i,vf]),'Exact converted value is not representable as a finite JSON decimal.','warning',False,{'rule_id':rid})); continue
                steps=[{'operation':'replace','path':pointer(decode_pointer(ap)+[i,vf]),'old_value':oldv,'new_value':nv,'metadata':{'rule_id':rid}},
                       {'operation':'replace','path':pointer(decode_pointer(ap)+[i,uf]),'old_value':oldu,'new_value':rule['canonical_unit'],'metadata':{'rule_id':rid}}]
                trial=deepcopy(root); inverses=[]; ok=True
                for p in steps:
                    yes,inv=apply_patch(trial,p); ok=ok and yes
                    if not yes: break
                    inverses.append(inv)
                meta={'rule_id':rid,'relation_id':rel['relation_id'],'relation_kind':kind,'constraint_source':'authoritative','steps':steps,'source_digest':digest(root),'target_digest':digest(trial),'inverse_steps':list(reversed(inverses))}
                path=pointer(decode_pointer(ap)+[i])
                out.issues.append(Issue('moments','unit_normalization_required',path,f'Normalize {oldu!r} to canonical unit {rule["canonical_unit"]!r}.','warning',bool(ok),meta))
                if ok:
                    cid=hashlib.sha1(json.dumps([rid,i,digest(root),digest(trial)],separators=(',',':')).encode()).hexdigest()[:16]
                    out.candidates.append(Candidate(cid,'moments','plan','',None,None,'Normalize value and unit atomically with path-local exact preconditions.',1.0,2,(f'MOMENT:{rid}',),meta))
                continue
            target=ev.get('target'); old=record.get(target); nv=_json_num(ev['expected'],[old] if old is not None else [])
            path=pointer(decode_pointer(ap)+[i,target])
            meta={'rule_id':rid,'relation_id':rel['relation_id'],'relation_kind':kind,'constraint_source':'authoritative','exact_expected_fraction':f'{ev["expected"].numerator}/{ev["expected"].denominator}',
                  'weight_sum_fraction':f'{ev.get("weight_sum",Fraction(0)).numerator}/{ev.get("weight_sum",Fraction(0)).denominator}' if ev.get('weight_sum') is not None else None,
                  'residue_fraction':None if ev.get('residue') is None else f'{ev["residue"].numerator}/{ev["residue"].denominator}', 'add_if_missing':target not in record}
            repairable=nv is not None
            code=f'{kind}_violation' if target in record else f'{kind}_missing'
            msg=f'Authoritative {kind} target does not match its exact local-to-aggregate bridge.'
            if nv is None: msg += ' Exact result is rational but not finitely representable as a JSON number; no mutation is proposed.'
            out.issues.append(Issue('moments',code,path,msg,'warning',repairable,meta))
            if repairable:
                cid=hashlib.sha1(json.dumps([rid,path,old,nv],sort_keys=True,default=str,separators=(',',':')).encode()).hexdigest()[:16]
                out.candidates.append(Candidate(cid,'moments','replace',path,old,nv,f'Restore authoritative exact {kind}.',1.0,1,(f'MOMENT:{rid}',),meta))
    if bool(getattr(config,'auto_moment_discovery',True)):
        inf=_inferred_moments(root,config); out.issues.extend(inf.issues); out.candidates.extend(inf.candidates); out.relations.extend(inf.relations)
    return out


def moment_summary(analysis:AnalysisResult)->dict[str,Any]:
    rels=[r for r in analysis.relations if r.get('bridge_kind')=='moment_distribution']
    return {'contract':'json-consistency-repair.moment-distribution-summary.v1','relation_count':len(rels),
            'weighted_mean_relations':sum(r.get('kind')=='weighted_mean_authoritative' for r in rels),
            'weighted_sum_relations':sum(r.get('kind')=='weighted_sum_authoritative' for r in rels),
            'variance_relations':sum(r.get('kind')=='variance_authoritative' for r in rels),
            'covariance_relations':sum(r.get('kind')=='covariance_authoritative' for r in rels),
            'probability_relations':sum(r.get('kind')=='probability_total_authoritative' for r in rels),
            'uncertainty_relations':sum(r.get('kind')=='uncertainty_variance_authoritative' for r in rels),
            'unit_relations':sum(r.get('kind')=='unit_normalize_authoritative' for r in rels),
            'violation_count':sum(i.analyzer=='moments' for i in analysis.issues),
            'repairable_violation_count':sum(i.analyzer=='moments' and i.repairable for i in analysis.issues)}


def _object_arrays(root: Any):
    out=[]
    def rec(v,parts):
        if isinstance(v,list) and len(v)>=3 and all(isinstance(x,dict) for x in v): out.append((parts,v))
        if isinstance(v,dict):
            for k,x in v.items(): rec(x,parts+[k])
        elif isinstance(v,list):
            for i,x in enumerate(v): rec(x,parts+[i])
    rec(root,[]); return out


def _inferred_moments(root:Any, config)->AnalysisResult:
    out=AnalysisResult(); min_support=max(3,int(getattr(config,'moment_min_support',4))); threshold=float(getattr(config,'moment_confidence',0.95)); max_fields=max(2,int(getattr(config,'moment_max_fields',8)))
    for parts,arr in _object_arrays(root):
        child_fields=[]
        for k in sorted(set().union(*(o.keys() for o in arr))):
            seen=sum(isinstance(o.get(k),list) and o[k] and all(isinstance(x,dict) for x in o[k]) for o in arr)
            if seen>=min_support: child_fields.append(k)
        parent_numeric=[k for k in sorted(set().union(*(o.keys() for o in arr))) if sum(_frac(o.get(k)) is not None for o in arr)>=min_support][:max_fields]
        for child in child_fields[:max_fields]:
            item_keys=Counter(); numeric=Counter()
            for o in arr:
                for it in o.get(child,[]) if isinstance(o.get(child),list) else []:
                    if isinstance(it,dict):
                        for k,v in it.items():
                            item_keys[k]+=1
                            if _frac(v) is not None: numeric[k]+=1
            nfields=[k for k,_ in numeric.most_common(max_fields)]
            # Weighted mean: target name is a direction witness; relation itself is certified by repeated exact equality.
            for target in parent_numeric:
                low=target.lower()
                if not ('mean' in low or 'average' in low or low in {'avg'}): continue
                for value_field in nfields:
                    for weight_field in nfields:
                        if value_field==weight_field: continue
                        rule={'kind':'weighted_mean','items_field':child,'value_field':value_field,'weight_field':weight_field,'target':target}
                        support=[]; violations=[]; exact_examples=[]
                        for i,o in enumerate(arr):
                            ev=evaluate_moment_rule(o,rule)
                            if ev.get('status') is True: support.append((i,o,ev)); exact_examples.append(o.get(target))
                            elif ev.get('status') is False: violations.append((i,o,ev)); exact_examples.append(o.get(target))
                        total=len(support)+len(violations)
                        if total<min_support or len(support)/total<threshold: continue
                        rel={'kind':'weighted_mean','array_path':pointer(parts),'inputs':[child,value_field,weight_field],'output':target,'confidence':round(len(support)/total,12),'support':len(support),'items_field':child,'value_field':value_field,'weight_field':weight_field,'bridge_kind':'moment_distribution','direction_certified':True,'direction_source':'aggregate_target_name'}
                        rel['relation_id']=_rid(rel); out.relations.append(rel)
                        for i,o,ev in violations:
                            nv=_json_num(ev['expected'],exact_examples); path=pointer(parts+[i,target]); meta={'relation_id':rel['relation_id'],'relation_kind':'weighted_mean','bridge_kind':'moment_distribution','direction_certified':True,'direction_source':'aggregate_target_name','exact_expected_fraction':f"{ev['expected'].numerator}/{ev['expected'].denominator}"}
                            out.issues.append(Issue('moments','weighted_mean_violation',path,'Parent weighted mean conflicts with the repeated exact local-to-aggregate relation.','warning',nv is not None,meta))
                            if nv is not None:
                                cid=hashlib.sha1(json.dumps(['moments',path,o.get(target),nv],sort_keys=True,default=str).encode()).hexdigest()[:16]
                                out.candidates.append(Candidate(cid,'moments','replace',path,o.get(target),nv,'Restore inferred exact weighted mean.',len(support)/total,1,(f"MOMENT:{rel['relation_id']}",),meta))
            # Variance sidecar inference only for target names that explicitly carry variance semantics; unweighted population variance.
            for target in parent_numeric:
                low=target.lower()
                if 'variance' not in low and low not in {'var'} and not low.endswith('_var'): continue
                for value_field in nfields:
                    rule={'kind':'variance','items_field':child,'value_field':value_field,'target':target,'ddof':0}
                    support=[]; violations=[]; ex=[]
                    for i,o in enumerate(arr):
                        ev=evaluate_moment_rule(o,rule)
                        if ev.get('status') is True: support.append((i,o,ev)); ex.append(o.get(target))
                        elif ev.get('status') is False: violations.append((i,o,ev)); ex.append(o.get(target))
                    total=len(support)+len(violations)
                    if total<min_support or len(support)/total<threshold: continue
                    rel={'kind':'variance','array_path':pointer(parts),'inputs':[child,value_field],'output':target,'confidence':round(len(support)/total,12),'support':len(support),'items_field':child,'value_field':value_field,'bridge_kind':'moment_distribution','direction_certified':True,'direction_source':'aggregate_target_name'}; rel['relation_id']=_rid(rel); out.relations.append(rel)
                    for i,o,ev in violations:
                        nv=_json_num(ev['expected'],ex); path=pointer(parts+[i,target]); meta={'relation_id':rel['relation_id'],'relation_kind':'variance','bridge_kind':'moment_distribution','direction_certified':True,'direction_source':'aggregate_target_name','exact_expected_fraction':f"{ev['expected'].numerator}/{ev['expected'].denominator}"}
                        out.issues.append(Issue('moments','variance_violation',path,'Variance sidecar conflicts with the repeated exact population variance relation.','warning',nv is not None,meta))
                        if nv is not None:
                            cid=hashlib.sha1(json.dumps(['moments',path,o.get(target),nv],sort_keys=True,default=str).encode()).hexdigest()[:16]
                            out.candidates.append(Candidate(cid,'moments','replace',path,o.get(target),nv,'Restore inferred exact variance sidecar.',len(support)/total,1,(f"MOMENT:{rel['relation_id']}",),meta))
    return out
