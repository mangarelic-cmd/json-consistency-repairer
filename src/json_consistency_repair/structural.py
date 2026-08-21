from __future__ import annotations
from collections import Counter
from copy import deepcopy
from typing import Any
import hashlib, json

from .models import AnalysisResult, Issue, Candidate, pointer


def object_arrays(root: Any):
    out=[]
    def rec(v, parts):
        if isinstance(v,list) and len(v)>=3 and all(isinstance(x,dict) for x in v):
            out.append((parts,v))
        if isinstance(v,dict):
            for k,x in v.items(): rec(x,parts+[k])
        elif isinstance(v,list):
            for i,x in enumerate(v): rec(x,parts+[i])
    rec(root,[])
    return out


def _cid(path, src, dst, value):
    raw=json.dumps(['structural_migration',path,src,dst,value],sort_keys=True,default=str,separators=(',',':')).encode()
    return hashlib.sha1(raw).hexdigest()[:16]


def _type_name(v): return type(v).__name__



def _name_affinity(a:str,b:str)->bool:
    import re
    def toks(x):
        return [t for t in re.split(r'[^a-z0-9]+',x.lower()) if t]
    ta,tb=toks(a),toks(b)
    if a.lower()==b.lower(): return True
    if a.lower().endswith('_'+b.lower()) or b.lower().endswith('_'+a.lower()): return True
    return any(x==y and len(x)>=3 for x in ta for y in tb)

def _expected_type(arr:list[dict], key:str):
    vals=[o[key] for o in arr if key in o and o[key] is not None]
    if not vals: return None,0.0,0
    c=Counter(_type_name(v) for v in vals); typ,n=c.most_common(1)[0]
    return typ,n/len(vals),n


def analyze_structural_migrations(root:Any,config)->AnalysisResult:
    """Discover only uniquely forced sibling-key renames/moves inside repeated object arrays.

    A move is proposed when a record has exactly one consensus-required key missing and exactly
    one non-consensus key extra, and the extra value matches the stable type of the missing key.
    This is intentionally narrow: multiple possible destinations => abstention.
    """
    r=AnalysisResult()
    min_support=max(4,int(getattr(config,'structural_move_min_support',4)))
    conf_req=float(getattr(config,'structural_move_confidence',0.95))
    for parts,arr in object_arrays(root):
        n=len(arr)
        counts=Counter(k for o in arr for k in o)
        consensus={k for k,c in counts.items() if c>=min_support and c/n>=conf_req}
        if not consensus: continue
        for i,o in enumerate(arr):
            missing=sorted(k for k in consensus if k not in o)
            extra=sorted(k for k in o if k not in consensus and counts[k] <= max(1,n-min_support+1))
            if len(missing)!=1 or len(extra)!=1: continue
            dst,src=missing[0],extra[0]
            if not _name_affinity(src,dst): continue
            expected_type,tconf,tsupport=_expected_type(arr,dst)
            value=o[src]
            if expected_type is None or tconf<conf_req or _type_name(value)!=expected_type: continue
            src_path=pointer(parts+[i,src]); dst_path=pointer(parts+[i,dst])
            meta={'from_path':src_path,'structural_kind':'unique_sibling_rename','support':counts[dst],
                  'type_support':tsupport,'type_confidence':tconf,'require_absent':True}
            issue=Issue('structural_migration','unique_key_migration',dst_path,
                        f"One consensus key {dst!r} is missing and exactly one extra key {src!r} uniquely carries a compatible value.",
                        'warning',True,meta)
            cand=Candidate(_cid(pointer(parts+[i]),src,dst,value),'structural_migration','move',dst_path,deepcopy(value),deepcopy(value),
                           f"Move uniquely matched structural value {src!r} -> {dst!r}.",1.0,1,
                           (f'SCHEMA_REQUIRED:{dst}',f'UNIQUE_EXTRA:{src}',f'TYPE:{expected_type}'),meta)
            r.issues.append(issue); r.candidates.append(cand)
            relation={'kind':'structural_move','array_path':pointer(parts),'inputs':[src],'output':dst,'confidence':1.0,'support':counts[dst],
                      'from_key':src,'to_key':dst,'direction_source':'unique_missing_extra_type_match'}
            ident={k:v for k,v in relation.items() if k not in {'confidence','support'}}
            relation['relation_id']=hashlib.sha1(json.dumps(ident,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:20]
            r.relations.append(relation)
    return r
