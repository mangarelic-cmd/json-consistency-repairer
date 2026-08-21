from __future__ import annotations
from collections import Counter, defaultdict
from dataclasses import replace
from typing import Any
import hashlib, json

from .models import AnalysisResult, Issue, Candidate, pointer

PREFERRED_DISCRIMINATORS=("type","kind","mode","schema_version","version","variant","record_type")
VERSION_NAMES={"schema_version","version","api_version","format_version"}


def _scalar(v:Any)->bool:
    return isinstance(v,(str,int,bool)) and v is not None


def _shape(o:dict)->tuple[str,...]:
    return tuple(sorted(o.keys()))


def _type_signature(o:dict)->tuple[tuple[str,str],...]:
    return tuple(sorted((k,type(v).__name__) for k,v in o.items() if v is not None))


def _group_score(arr:list[dict], field:str) -> tuple[float,float]:
    # explanatory gain from structure/type coherence after partitioning.
    global_shape=Counter(_shape(o) for o in arr).most_common(1)[0][1]/len(arr)
    global_type=Counter(_type_signature(o) for o in arr).most_common(1)[0][1]/len(arr)
    groups=defaultdict(list)
    for o in arr:
        groups[json.dumps(o[field],sort_keys=True,ensure_ascii=False)].append(o)
    shape=sum(len(g)*(Counter(_shape(o) for o in g).most_common(1)[0][1]/len(g)) for g in groups.values())/len(arr)
    typ=sum(len(g)*(Counter(_type_signature(o) for o in g).most_common(1)[0][1]/len(g)) for g in groups.values())/len(arr)
    return shape-global_shape, typ-global_type


def detect_regime(parts:list[str|int], arr:list[dict], config) -> dict[str,Any] | None:
    min_support=max(3,int(getattr(config,"modal_min_support",config.min_support)))
    min_regime=max(2,int(getattr(config,"modal_min_regime_support",2)))
    if len(arr)<min_support: return None
    keys=sorted(set.intersection(*(set(o.keys()) for o in arr))) if arr else []
    candidates=[]
    for field in keys:
        vals=[o.get(field) for o in arr]
        if not all(_scalar(v) for v in vals): continue
        counts=Counter(json.dumps(v,sort_keys=True,ensure_ascii=False) for v in vals)
        if not (2<=len(counts)<=int(getattr(config,"modal_max_regimes",8))): continue
        if min(counts.values())<min_regime: continue
        shape_gain,type_gain=_group_score(arr,field)
        preferred=field in PREFERRED_DISCRIMINATORS or field.lower() in PREFERRED_DISCRIMINATORS
        # status-like fields are never modalized merely by name; they need actual explanatory gain.
        if not preferred and max(shape_gain,type_gain)<float(getattr(config,"modal_min_gain",0.10)): continue
        if preferred and field.lower()=="status" and max(shape_gain,type_gain)<float(getattr(config,"modal_min_gain",0.10)): continue
        score=(1 if preferred else 0, round(max(shape_gain,type_gain),12), -len(counts), field)
        candidates.append((score,field,counts,shape_gain,type_gain))
    if not candidates: return None
    _,field,counts,sg,tg=max(candidates,key=lambda x:x[0])
    groups=defaultdict(list)
    for i,o in enumerate(arr): groups[json.dumps(o[field],sort_keys=True,ensure_ascii=False)].append(i)
    return {"array_parts":list(parts),"array_path":pointer(parts),"field":field,"groups":{k:v for k,v in sorted(groups.items())},
            "shape_gain":round(sg,12),"type_gain":round(tg,12),"coverage":1.0}


def _remap_pointer(local_path:str, array_parts:list[str|int], index_map:list[int]) -> str:
    if local_path=="": return pointer(array_parts)
    toks=[x.replace("~1","/").replace("~0","~") for x in local_path[1:].split("/")]
    if not toks: return pointer(array_parts)
    try: first=int(toks[0])
    except Exception: return pointer(array_parts)+local_path
    if first<0 or first>=len(index_map): return pointer(array_parts)+local_path
    return pointer(array_parts+[index_map[first]]+toks[1:])


def _remap_relation(rel:dict[str,Any], array_parts:list[str|int], index_map:list[int], field:str, value:Any) -> dict[str,Any]:
    out=dict(rel)
    out["array_path"]=_remap_pointer(str(rel.get("array_path","")),array_parts,index_map)
    out["regime_field"]=field; out["regime_value"]=value; out["modalized"]=True
    ident={k:v for k,v in out.items() if k not in {"confidence","support","relation_id","direction_confidence","direction_seen"}}
    out["relation_id"]=hashlib.sha1(json.dumps(ident,sort_keys=True,default=str,separators=(",",":")).encode()).hexdigest()[:20]
    return out


def modal_analyze(root:Any, config, object_arrays_fn, sensitive_analyzers:list[Any], ordinary_analyzers:list[Any]) -> AnalysisResult:
    out=AnalysisResult()
    # Non-sensitive analyzers always see the sovereign object.
    for a in ordinary_analyzers:
        z=a.analyze(root,config); out.issues.extend(z.issues); out.candidates.extend(z.candidates); out.relations.extend(z.relations)

    arrays=object_arrays_fn(root); modal_paths={}
    for parts,arr in arrays:
        reg=detect_regime(parts,arr,config)
        if reg: modal_paths[pointer(parts)]=(reg,arr)

    # Sensitive analyzers run globally only for non-modalized arrays, and per regime for modalized arrays.
    global_result=AnalysisResult()
    for a in sensitive_analyzers:
        z=a.analyze(root,config); global_result.issues.extend(z.issues); global_result.candidates.extend(z.candidates); global_result.relations.extend(z.relations)
    if not modal_paths:
        out.issues.extend(global_result.issues); out.candidates.extend(global_result.candidates); out.relations.extend(global_result.relations)
        return out

    def governed(path:str)->bool:
        return any(path==p or path.startswith(p+"/") for p in modal_paths)
    # Keep global sensitive findings outside any modalized population.
    out.issues.extend(i for i in global_result.issues if not governed(i.path))
    out.candidates.extend(c for c in global_result.candidates if not governed(c.path))
    out.relations.extend(r for r in global_result.relations if not governed(str(r.get("array_path",""))))

    for ap,(reg,arr) in sorted(modal_paths.items()):
        field=reg["field"]
        for raw,idxs in reg["groups"].items():
            value=json.loads(raw); rows=[arr[i] for i in idxs]
            ident={"kind":"modal_regime","array_path":ap,"field":field,"value":value}
            rid=hashlib.sha1(json.dumps(ident,sort_keys=True,separators=(",",":")).encode()).hexdigest()[:20]
            out.relations.append({**ident,"regime_field":field,"regime_value":value,"inputs":[field],"output":"__regime__","confidence":1.0,"support":len(rows),"relation_id":rid,
                                  "shape_gain":reg["shape_gain"],"type_gain":reg["type_gain"]})
            for a in sensitive_analyzers:
                z=a.analyze(rows,config)
                for issue in z.issues:
                    out.issues.append(replace(issue,path=_remap_pointer(issue.path,reg["array_parts"],idxs),
                                              metadata={**issue.metadata,"regime_field":field,"regime_value":value}))
                for c in z.candidates:
                    out.candidates.append(replace(c,path=_remap_pointer(c.path,reg["array_parts"],idxs),
                                                  metadata={**c.metadata,"regime_field":field,"regime_value":value}))
                for rel in z.relations:
                    out.relations.append(_remap_relation(rel,reg["array_parts"],idxs,field,value))
        if field.lower() in VERSION_NAMES:
            shapes={raw:Counter(_shape(arr[i]) for i in idxs).most_common(1)[0][0] for raw,idxs in reg["groups"].items()}
            ident={"kind":"schema_evolution","array_path":ap,"version_field":field,"shapes":{k:list(v) for k,v in sorted(shapes.items())}}
            ident["inputs"]=[field]; ident["output"]="__schema__"; ident["confidence"]=1.0; ident["support"]=len(arr)
            ident["relation_id"]=hashlib.sha1(json.dumps({k:v for k,v in ident.items() if k not in {"confidence","support"}},sort_keys=True,separators=(",",":")).encode()).hexdigest()[:20]
            out.relations.append(ident)
    return out


def recursive_morphology(root:Any, config) -> AnalysisResult:
    out=AnalysisResult(); min_support=max(3,int(getattr(config,"morphology_min_support",3)))
    def visit(node:Any, path:list[str|int], family_key:str|None=None):
        if not isinstance(node,dict): return
        for key,val in list(node.items()):
            if isinstance(val,list) and len(val)>=min_support and all(isinstance(x,dict) for x in val):
                # recurrent family if at least one child contains the same container key, or shapes recur strongly.
                shapes=Counter(_shape(x) for x in val); dom,n=shapes.most_common(1)[0]
                recurrent=any(key in x and isinstance(x.get(key),list) for x in val) or n/len(val)>=0.75
                if recurrent:
                    ident={"kind":"recursive_morphology","array_path":pointer(path+[key]),"container_key":key,"dominant_keys":list(dom)}
                    ident["inputs"]=[key]; ident["output"]="__morphology__"; ident["confidence"]=round(n/len(val),12); ident["support"]=n
                    ident["relation_id"]=hashlib.sha1(json.dumps({k:v for k,v in ident.items() if k not in {"confidence","support"}},sort_keys=True,separators=(",",":")).encode()).hexdigest()[:20]
                    out.relations.append(ident)
                    required=[k for k in dom if sum(1 for x in val if k in x)/len(val)>=0.95]
                    for i,x in enumerate(val):
                        for req in required:
                            if req not in x:
                                p=pointer(path+[key,i,req])
                                out.issues.append(Issue("recursive_morphology","recursive_morphology_missing_key",p,
                                    f"Recurrent structure is missing key {req!r}; morphology alone does not determine its value.","warning",False,
                                    {"container_key":key,"schema_key":req,"relation_kind":"recursive_morphology"}))
                for i,x in enumerate(val): visit(x,path+[key,i],key)
            elif isinstance(val,dict): visit(val,path+[key],family_key)
    visit(root,[])
    return out
