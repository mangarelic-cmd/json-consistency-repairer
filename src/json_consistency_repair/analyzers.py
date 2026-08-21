from __future__ import annotations
from collections import Counter, defaultdict
from itertools import combinations
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any
from contextvars import ContextVar
import hashlib, json
from .models import Issue, Candidate, AnalysisResult, pointer
from .exactmath import decimal_of, canonical_number_like
from .logic_exact import evaluate_rule, repair_candidates_for_rule, rule_system_certificate, stable_rule_id
from .conservation import (
    stable_conservation_id, aggregate_target_hint, sum_child_values, child_count,
    scalar_balance_residue, multiset_map, multiset_residue, evaluate_conservation_rule, conservation_rule_patch,
)


def cid(analyzer, path, old, new):
    raw=json.dumps([analyzer,path,old,new],sort_keys=True,default=str,separators=(",",":")).encode()
    return hashlib.sha1(raw).hexdigest()[:16]


def cand(analyzer,path,old,new,reason,*,confidence=1.0,evidence=(),metadata=None):
    return Candidate(cid(analyzer,path,old,new), analyzer, "replace", path, old, new, reason, confidence, 1, tuple(evidence), metadata or {})


_OBJECT_ARRAY_SCAN: ContextVar[tuple[Any,list]|None] = ContextVar("json_consistency_repair_object_arrays", default=None)

def _compute_object_arrays(root: Any):
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

def object_arrays(root: Any):
    cached=_OBJECT_ARRAY_SCAN.get()
    if cached is not None and cached[0] is root:
        return cached[1]
    return _compute_object_arrays(root)


def _jkey(v:Any):
    try: return json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(",",":"))
    except TypeError: return None


def _scalar(v:Any):
    return isinstance(v,(str,int,float,bool)) and v is not None


def _rel(kind,array_parts,inputs,output,confidence,support,**extra):
    d={"kind":kind,"array_path":pointer(array_parts),"inputs":list(inputs),"output":output,"confidence":round(float(confidence),12),"support":int(support)}
    d.update(extra)
    # Relation identity names the invariant itself, not the current amount of evidence for it.
    # This lets the cumulative knowledge ledger track one relation becoming stronger across cycles.
    identity={k:v for k,v in d.items() if k not in {"confidence","support","direction_confidence","direction_seen"}}
    raw=json.dumps(identity,sort_keys=True,default=str,separators=(",",":")).encode()
    d["relation_id"]=hashlib.sha1(raw).hexdigest()[:20]
    return d


def _field_order_direction(arr:list[dict], target:str, inputs:list[str], positions:list[dict[str,int]]|None=None) -> tuple[float,int]:
    """Weak causal-direction witness from consistently preserved source key order.

    JSON semantics do not make object order meaningful, so this is never treated as an
    equation proof by itself. It is only a direction witness after the equation itself
    has already been certified across records.  ``positions`` lets hot-path analyzers
    reuse one key-order projection instead of rebuilding/indexing key lists per formula.
    """
    seen=0; forward=0
    if positions is None:
        positions=[{k:i for i,k in enumerate(o.keys())} for o in arr]
    for pos in positions:
        tp=pos.get(target)
        if tp is None or any(k not in pos for k in inputs): continue
        seen+=1
        if all(pos[k]<tp for k in inputs): forward+=1
    return (forward/seen if seen else 0.0), seen


def _sparse_functional_recovery(mapping:dict, observed:int, confidence:float, config) -> tuple[bool,dict[str,Any]]:
    """Bounded fallback for sparse heterogeneous outliers.

    This is intentionally not a generic threshold reduction.  A determinant group is
    admissible only when its modal value is a strict repeated carrier and every competing
    value is individually sparse.  PASS037's active relation falsifier must remain enabled;
    otherwise the fallback is unavailable.
    """
    if not bool(getattr(config,"enable_sparse_outlier_recovery",False)):
        return False,{"reason":"DISABLED"}
    if not bool(getattr(config,"enable_relation_falsifier",True)):
        return False,{"reason":"FALSIFIER_REQUIRED"}
    floor=float(getattr(config,"sparse_outlier_confidence_floor",0.60))
    if observed <= 0 or confidence < floor:
        return False,{"reason":"BELOW_SPARSE_FLOOR","floor":floor}
    min_mode=max(int(getattr(config,"min_group_support",3)),int(getattr(config,"sparse_outlier_min_mode_support",3)))
    min_margin=max(1,int(getattr(config,"sparse_outlier_min_mode_margin",2)))
    max_alt=max(0,int(getattr(config,"sparse_outlier_max_alternative_count",1)))
    rows=[]
    for key,counter in sorted(mapping.items(),key=lambda kv:str(kv[0])):
        total=sum(counter.values())
        if total < int(getattr(config,"min_group_support",3)):
            return False,{"reason":"GROUP_SUPPORT_TOO_SMALL","determinant_value":key,"support":total}
        ranked=counter.most_common()
        if not ranked:
            return False,{"reason":"EMPTY_GROUP","determinant_value":key}
        top_value,top_n=ranked[0]
        second_n=ranked[1][1] if len(ranked)>1 else 0
        alternatives=ranked[1:]
        if top_n < min_mode:
            return False,{"reason":"MODE_SUPPORT_TOO_SMALL","determinant_value":key,"mode_support":top_n,"required":min_mode}
        if top_n-second_n < min_margin:
            return False,{"reason":"MODE_MARGIN_TOO_SMALL","determinant_value":key,"mode_support":top_n,"second_support":second_n,"required_margin":min_margin}
        if any(n>max_alt for _,n in alternatives):
            return False,{"reason":"COHERENT_ALTERNATIVE_PRESENT","determinant_value":key,"max_allowed_alternative_count":max_alt}
        rows.append({"determinant_value":key,"support":total,"mode_support":top_n,"second_support":second_n,"alternative_count":sum(n for _,n in alternatives)})
    return bool(rows),{"reason":"SPARSE_HETEROGENEOUS_OUTLIERS","floor":floor,"groups":rows}


def _sparse_arithmetic_recovery(support:list, violations:list, confidence:float, structural_direction:bool, config) -> tuple[bool,dict[str,Any]]:
    """Exact-equation fallback when non-zero residuals are sparse and non-coherent."""
    if not bool(getattr(config,"enable_sparse_outlier_recovery",False)):
        return False,{"reason":"DISABLED"}
    if not bool(getattr(config,"enable_relation_falsifier",True)):
        return False,{"reason":"FALSIFIER_REQUIRED"}
    floor=float(getattr(config,"sparse_outlier_confidence_floor",0.60))
    if confidence < floor:
        return False,{"reason":"BELOW_SPARSE_FLOOR","floor":floor}
    if not structural_direction:
        return False,{"reason":"STRUCTURAL_DIRECTION_REQUIRED"}
    min_mode=max(int(getattr(config,"min_support",4)),int(getattr(config,"sparse_outlier_min_mode_support",3)))
    if len(support) < min_mode:
        return False,{"reason":"EXACT_SUPPORT_TOO_SMALL","support":len(support),"required":min_mode}
    max_alt=max(0,int(getattr(config,"sparse_outlier_max_alternative_count",1)))
    min_margin=max(1,int(getattr(config,"sparse_outlier_min_mode_margin",2)))
    residuals=Counter()
    for _,_,exp,actual in violations:
        try: residuals[str(actual-exp)] += 1
        except Exception: residuals[f"{actual!r}!={exp!r}"] += 1
    second=max(residuals.values(),default=0)
    if second>max_alt:
        return False,{"reason":"COHERENT_NONZERO_RESIDUAL_PRESENT","max_residual_support":second,"allowed":max_alt}
    if len(support)-second < min_margin:
        return False,{"reason":"EXACT_MODE_MARGIN_TOO_SMALL","support":len(support),"second_support":second,"required_margin":min_margin}
    return True,{"reason":"SPARSE_HETEROGENEOUS_RESIDUALS","floor":floor,"exact_support":len(support),"violation_count":len(violations),"max_nonzero_residual_support":second}


class TypePatternAnalyzer:
    name="type_pattern"
    def analyze(self,root,config):
        r=AnalysisResult()
        for parts,arr in object_arrays(root):
            keys=Counter(k for obj in arr for k in obj)
            for key,_ in keys.items():
                vals=[obj[key] for obj in arr if key in obj and obj[key] is not None]
                if len(vals)<config.min_support: continue
                types=Counter(type(v).__name__ for v in vals)
                majority,n=types.most_common(1)[0]
                conf=n/len(vals)
                if conf < config.type_confidence: continue
                r.relations.append(_rel("type_consensus",parts,[],key,conf,n,dominant_type=majority))
                for i,obj in enumerate(arr):
                    if key in obj and obj[key] is not None and type(obj[key]).__name__ != majority:
                        path=pointer(parts+[i,key]); old=obj[key]
                        r.issues.append(Issue(self.name,"type_outlier",path,f"Value type {type(old).__name__} conflicts with dominant type {majority}.","warning",False,{"dominant":majority,"support":n,"observed":len(vals)}))
        return r


class FunctionalRelationAnalyzer:
    name="functional_relation"
    def analyze(self,root,config):
        r=AnalysisResult()
        for parts,arr in object_arrays(root):
            common=[k for k in set().union(*(o.keys() for o in arr)) if sum(k in o for o in arr)>=config.min_support]
            common=sorted(common)[:config.max_relation_fields]
            # Canonicalize each populated cell once per array.  Functional discovery
            # compares the same cells across O(fields^2) determinant/target pairs;
            # re-running json.dumps in every pair was pure repeated work.
            jcols={k:[_jkey(o[k]) if k in o and o[k] is not None else None for o in arr] for k in common}
            for det in common:
                dcol=jcols[det]
                for target in common:
                    if det==target: continue
                    tcol=jcols[target]
                    mapping=defaultdict(Counter); observed=0
                    for i,o in enumerate(arr):
                        dk,tv=dcol[i],tcol[i]
                        if dk is None or tv is None: continue
                        mapping[dk][tv]+=1; observed+=1
                    if observed<config.min_support: continue
                    good={k:v.most_common(1)[0] for k,v in mapping.items() if sum(v.values())>=config.min_group_support}
                    if not good: continue
                    agreements=sum(n for _,n in good.values()); conf=agreements/observed
                    sparse_ok,sparse_cert=_sparse_functional_recovery(mapping,observed,conf,config)
                    standard_ok=conf >= config.relation_confidence
                    if not standard_ok and not sparse_ok: continue
                    recovery_route="STANDARD_CONFIDENCE" if standard_ok else "SPARSE_OUTLIER_RECOVERY"
                    r.relations.append(_rel("functional",parts,[det],target,conf,agreements,determinant=det,groups=len(good),
                                            recovery_route=recovery_route,sparse_outlier_certificate=sparse_cert if sparse_ok else None))
                    for i,o in enumerate(arr):
                        dk=dcol[i]
                        if dk is None or dk not in good: continue
                        tv,n=good[dk]; expected=json.loads(tv)
                        meta={"determinant":det,"target":target,"support":n,"relation_kind":"functional","recovery_route":recovery_route}
                        if target not in o or o[target] is None:
                            path=pointer(parts+[i,target]); old=o.get(target,None); meta["add_if_missing"]=target not in o
                            r.issues.append(Issue(self.name,"missing_from_functional_relation",path,"Missing value is determined by a stable functional relation.","warning",True,meta))
                            r.candidates.append(cand(self.name,path,old,expected,f"Reconstruct {target!r} from stable mapping {det!r}->{target!r}.",confidence=conf,evidence=(f"FD:{det}->{target}",),metadata=meta))
                        elif o[target] != expected:
                            path=pointer(parts+[i,target]); old=o[target]
                            r.issues.append(Issue(self.name,"functional_relation_violation",path,"Value violates a stable functional relation.","warning",True,meta))
                            r.candidates.append(cand(self.name,path,old,expected,f"Restore stable mapping {det!r}->{target!r}.",confidence=conf,evidence=(f"FD:{det}->{target}",),metadata=meta))
        return r


class ScopedFunctionalRelationAnalyzer:
    name="scoped_functional_relation"
    def analyze(self,root,config):
        r=AnalysisResult()
        for parts,arr in object_arrays(root):
            keys=sorted(set().union(*(o.keys() for o in arr)))[:config.max_relation_fields]
            scalar_keys=[k for k in keys if sum(_scalar(o.get(k)) for o in arr)>=config.min_support]
            jcols={k:[_jkey(o[k]) if k in o and o[k] is not None else None for o in arr] for k in keys}
            for scope in scalar_keys:
                scopes=defaultdict(list)
                scol=jcols[scope]
                for i,o in enumerate(arr):
                    if _scalar(o.get(scope)): scopes[scol[i]].append((i,o))
                viable={s:rows for s,rows in scopes.items() if len(rows)>=config.min_scope_support}
                if not viable: continue
                for det in keys:
                    if det==scope: continue
                    for target in keys:
                        if target in (scope,det): continue
                        any_relation=False
                        for sval,rows in viable.items():
                            mapping=defaultdict(Counter); observed=0
                            dcol=jcols[det]; tcol=jcols[target]
                            for i,o in rows:
                                dk,tv=dcol[i],tcol[i]
                                if dk is None or tv is None: continue
                                mapping[dk][tv]+=1; observed+=1
                            if observed<config.min_scope_support: continue
                            good={k:v.most_common(1)[0] for k,v in mapping.items() if sum(v.values())>=config.min_scope_group_support}
                            if not good: continue
                            agreements=sum(n for _,n in good.values()); conf=agreements/observed
                            if conf<config.scoped_relation_confidence: continue
                            any_relation=True
                            scope_value=json.loads(sval)
                            r.relations.append(_rel("scoped_functional",parts,[scope,det],target,conf,agreements,scope_field=scope,scope_value=scope_value,determinant=det,groups=len(good)))
                            for i,o in rows:
                                dk=dcol[i]
                                if dk is None or dk not in good: continue
                                tv,n=good[dk]; expected=json.loads(tv)
                                meta={"scope_field":scope,"scope_value":scope_value,"determinant":det,"target":target,"support":n,"relation_kind":"scoped_functional"}
                                if target not in o or o[target] is None:
                                    path=pointer(parts+[i,target]); old=o.get(target); meta["add_if_missing"]=target not in o
                                    r.issues.append(Issue(self.name,"missing_from_scoped_relation",path,"Missing value is determined inside its stable scope.","warning",True,meta))
                                    r.candidates.append(cand(self.name,path,old,expected,"Restore scoped functional invariant.",confidence=conf,evidence=(f"SFD:{scope}={sval}:{det}->{target}",),metadata=meta))
                                elif o[target]!=expected:
                                    path=pointer(parts+[i,target])
                                    r.issues.append(Issue(self.name,"scoped_relation_violation",path,"Value violates a stable relation inside its scope.","warning",True,meta))
                                    r.candidates.append(cand(self.name,path,o[target],expected,"Restore scoped functional invariant.",confidence=conf,evidence=(f"SFD:{scope}={sval}:{det}->{target}",),metadata=meta))
        return r


class SchemaStructureAnalyzer:
    name="schema_structure"
    def analyze(self, root, config):
        r=AnalysisResult()
        for parts,arr in object_arrays(root):
            n=len(arr)
            if n < config.min_support: continue
            key_counts=Counter(k for o in arr for k in o)
            shapes=Counter(tuple(sorted(o.keys())) for o in arr)
            shape,nshape=shapes.most_common(1)[0]
            shape_conf=nshape/n
            if shape_conf >= config.shape_confidence:
                r.relations.append(_rel("dominant_shape",parts,[],"__shape__",shape_conf,nshape,keys=list(shape)))
            for key,count in sorted(key_counts.items()):
                conf=count/n
                if conf < config.required_key_confidence: continue
                r.relations.append(_rel("required_key",parts,[],key,conf,count,schema_key=key))
                for i,o in enumerate(arr):
                    if key in o: continue
                    path=pointer(parts+[i,key])
                    meta={"schema_key":key,"support":count,"observed":n,"relation_kind":"required_key","add_if_missing":True}
                    # Structure proves absence, not the missing value. Other analyzers may independently fix it.
                    r.issues.append(Issue(self.name,"missing_required_key",path,
                        f"Key {key!r} is structurally required by the dominant record shape, but its value is not determined by shape alone.",
                        "warning",False,meta))
        return r


class EnumDomainAnalyzer:
    name="enum_domain"
    def analyze(self, root, config):
        r=AnalysisResult()
        for parts,arr in object_arrays(root):
            keys=sorted(set().union(*(o.keys() for o in arr)))
            for key in keys:
                vals=[o.get(key) for o in arr if isinstance(o.get(key),str)]
                if len(vals)<config.min_support: continue
                counts=Counter(vals)
                canonical={v:n for v,n in counts.items() if n>=config.enum_min_value_support}
                if not canonical or len(canonical)>config.enum_max_values: continue
                # Avoid treating free text as an enum merely because some sentences repeat.
                if len(canonical) > max(1, len(vals)//2): continue
                domain=set(canonical)
                folded=defaultdict(list)
                for v in domain: folded[v.casefold()].append(v)
                recognized=0
                for v in vals:
                    if v in domain:
                        recognized+=1; continue
                    matches=folded.get(v.casefold(),[])
                    if len(matches)==1:
                        canon=matches[0]
                        cluster_total=counts[v]+counts[canon]
                        if counts[canon]/cluster_total >= config.enum_normalization_confidence:
                            recognized+=1
                conf=recognized/len(vals)
                if conf<config.enum_confidence: continue
                domain_sorted=sorted(domain)
                domain_id=hashlib.sha1(json.dumps(domain_sorted,ensure_ascii=False,separators=(",",":")).encode()).hexdigest()[:12]
                r.relations.append(_rel("enum_domain",parts,[],key,conf,sum(canonical.values()),domain=domain_sorted,domain_id=domain_id))
                for i,o in enumerate(arr):
                    v=o.get(key)
                    if not isinstance(v,str) or v in domain: continue
                    meta={"enum_field":key,"domain_id":domain_id,"domain":domain_sorted,"relation_kind":"enum_domain"}
                    matches=folded.get(v.casefold(),[])
                    if len(matches)==1:
                        canon=matches[0]
                        cluster_total=counts[v]+counts[canon]
                        canon_conf=counts[canon]/cluster_total
                        if canon_conf >= config.enum_normalization_confidence:
                            path=pointer(parts+[i,key]); meta["canonicalization_confidence"]=round(canon_conf,12)
                            r.issues.append(Issue(self.name,"enum_representation_variant",path,
                                f"Value {v!r} is a non-canonical representation of certified enum value {canon!r}.",
                                "warning",True,meta))
                            r.candidates.append(cand(self.name,path,v,canon,"Canonicalize enum representation without changing enum identity.",
                                                     confidence=min(conf,canon_conf),evidence=(f"ENUM:{key}:{domain_id}","CASEFOLD_UNIQUE"),metadata=meta))
                            continue
                    path=pointer(parts+[i,key])
                    r.issues.append(Issue(self.name,"enum_domain_outlier",path,
                        f"Value {v!r} is outside the certified low-cardinality domain; no unique replacement is justified.",
                        "warning",False,meta))
        return r


def _singular(name:str) -> str:
    if name.endswith("ies") and len(name)>3: return name[:-3]+"y"
    if name.endswith("ses") and len(name)>3: return name[:-2]
    if name.endswith("s") and not name.endswith("ss") and len(name)>1: return name[:-1]
    return name


class IdentifierReferenceAnalyzer:
    name="identifier_reference"
    def analyze(self, root, config):
        r=AnalysisResult()
        arrays=object_arrays(root)
        registries=[]
        local_pk={}
        for parts,arr in arrays:
            keys=sorted(set().union(*(o.keys() for o in arr)))
            last=str(parts[-1]) if parts and not isinstance(parts[-1],int) else ""
            preferred=[]
            for k in ("id","uuid",f"{_singular(last)}_id" if last else None,f"{_singular(last)}_uuid" if last else None):
                if k and k in keys and k not in preferred: preferred.append(k)
            for key in preferred:
                vals=[o.get(key) for o in arr if o.get(key) is not None and _jkey(o.get(key)) is not None]
                if len(vals)<config.min_support: continue
                encoded=[_jkey(v) for v in vals]; distinct=len(set(encoded)); conf=distinct/len(encoded)
                if conf < config.id_uniqueness_confidence: continue
                r.relations.append(_rel("identifier_uniqueness",parts,[key],key,conf,distinct,id_field=key))
                positions=defaultdict(list)
                for i,o in enumerate(arr):
                    if o.get(key) is not None: positions[_jkey(o.get(key))].append(i)
                dup={v:idxs for v,idxs in positions.items() if len(idxs)>1}
                for ev,idxs in dup.items():
                    for i in idxs:
                        path=pointer(parts+[i,key])
                        r.issues.append(Issue(self.name,"duplicate_identifier",path,
                            f"Identifier {json.loads(ev)!r} is duplicated in a field whose observed uniqueness is {conf:.3f}; no occurrence can be selected as wrong automatically.",
                            "error",False,{"id_field":key,"duplicate_indices":idxs,"relation_kind":"identifier_uniqueness"}))
                if conf==1.0:
                    registry={"parts":parts,"path":pointer(parts),"field":key,"values":{_jkey(v):v for v in vals},"raw":vals}
                    registries.append(registry); local_pk[pointer(parts)]=key
                    break

        # Discover references by value overlap, not by guessed entity names alone.
        for parts,arr in arrays:
            arr_path=pointer(parts); keys=sorted(set().union(*(o.keys() for o in arr)))
            for field in keys:
                if field==local_pk.get(arr_path): continue
                if not (field.endswith("_id") or field.endswith("_uuid") or field in ("parent_id","ref_id")): continue
                refs=[o.get(field) for o in arr if o.get(field) is not None and _jkey(o.get(field)) is not None]
                if len(refs)<config.min_support: continue
                scored=[]
                for reg in registries:
                    if reg["path"]==arr_path and reg["field"]==field: continue
                    overlap=sum(1 for v in refs if _jkey(v) in reg["values"])
                    conf=overlap/len(refs)
                    if conf>=config.reference_confidence: scored.append((conf,overlap,reg))
                if not scored: continue
                scored.sort(key=lambda x:(-x[0],-x[1],x[2]["path"],x[2]["field"]))
                best=scored[0]
                if len(scored)>1 and scored[1][0]==best[0] and scored[1][1]==best[1]:
                    continue  # ambiguous target registry
                conf,overlap,reg=best
                target_values=reg["values"]
                casefold={}
                if all(isinstance(v,str) for v in reg["raw"]):
                    tmp=defaultdict(list)
                    for v in reg["raw"]: tmp[v.casefold()].append(v)
                    casefold={k:vs[0] for k,vs in tmp.items() if len(vs)==1}
                r.relations.append(_rel("foreign_reference",parts,[field],field,conf,overlap,
                                        reference_field=field,target_array_path=reg["path"],target_id_field=reg["field"]))
                for i,o in enumerate(arr):
                    if field not in o or o[field] is None: continue
                    v=o[field]
                    if _jkey(v) in target_values: continue
                    meta={"reference_field":field,"target_array_path":reg["path"],"target_id_field":reg["field"],"relation_kind":"foreign_reference"}
                    path=pointer(parts+[i,field])
                    if isinstance(v,str) and v.casefold() in casefold:
                        canon=casefold[v.casefold()]
                        r.issues.append(Issue(self.name,"reference_representation_variant",path,
                            f"Reference {v!r} uniquely matches canonical identifier {canon!r} after representation normalization.",
                            "error",True,meta))
                        r.candidates.append(cand(self.name,path,v,canon,"Restore canonical foreign-reference representation.",
                                                 confidence=conf,evidence=(f"FK:{field}->{reg['path']}#{reg['field']}","CASEFOLD_UNIQUE_ID"),metadata=meta))
                    else:
                        r.issues.append(Issue(self.name,"dangling_reference",path,
                            f"Reference {v!r} does not resolve in certified identifier set {reg['path']}#{reg['field']}; no unique replacement is justified.",
                            "error",False,meta))
        return r


class ExactArithmeticAnalyzer:
    name="exact_arithmetic"
    OPS=(
        ("+", lambda a,b:a+b, False),
        ("-", lambda a,b:a-b, True),
        ("*", lambda a,b:a*b, False),
        ("/", lambda a,b:None if b==0 else a/b, True),
    )
    def analyze(self,root,config):
        r=AnalysisResult()
        for parts,arr in object_arrays(root):
            keys=sorted(set().union(*(o.keys() for o in arr)))
            # PASS041 hot path: decimal conversion is a pure projection. Compute it
            # once per cell instead of once per candidate equation/operator.
            decimal_columns={k:[decimal_of(o.get(k)) for o in arr] for k in keys}
            numeric=[k for k in keys if sum(v is not None for v in decimal_columns[k])>=config.min_support]
            if len(numeric)>config.max_numeric_fields: numeric=numeric[:config.max_numeric_fields]
            equations=[]; direction_cache={}
            key_positions=[{k:i for i,k in enumerate(o.keys())} for o in arr]
            for target in numeric:
                others=[k for k in numeric if k!=target]
                target_examples=[o.get(target) for i,o in enumerate(arr) if decimal_columns[target][i] is not None]
                seen_formula=set()
                for a in others:
                    for b in others:
                        if a==b: continue
                        for symbol,fn,ordered in self.OPS:
                            if not ordered and b<a: continue
                            formula=(target,a,symbol,b)
                            if formula in seen_formula: continue
                            seen_formula.add(formula)
                            support=[]; violations=[]; missing=[]
                            ca,cb,ct=decimal_columns[a],decimal_columns[b],decimal_columns[target]
                            for i,o in enumerate(arr):
                                da,db,dt=ca[i],cb[i],ct[i]
                                if da is None or db is None: continue
                                exp=fn(da,db)
                                if exp is None: continue
                                if dt is None: missing.append((i,o,exp))
                                elif dt==exp: support.append(i)
                                else: violations.append((i,o,exp,dt))
                            total=len(support)+len(violations)
                            if total<config.min_support: continue
                            conf=len(support)/total
                            ftxt=f"EXACT:{target}={a}{symbol}{b}"
                            dkey=(target,a,b)
                            if dkey not in direction_cache:
                                direction_cache[dkey]=_field_order_direction(arr,target,[a,b],key_positions)
                            dconf,dseen=direction_cache[dkey]
                            structural_direction=dseen>=config.min_support and dconf>=config.arithmetic_direction_confidence
                            sparse_ok,sparse_cert=_sparse_arithmetic_recovery(support,violations,conf,structural_direction,config)
                            standard_ok=conf>=config.arithmetic_confidence
                            if not standard_ok and not sparse_ok: continue
                            recovery_route="STANDARD_CONFIDENCE" if standard_ok else "SPARSE_OUTLIER_RECOVERY"
                            equations.append({"target":target,"a":a,"b":b,"symbol":symbol,"support":support,
                                              "violations":violations,"missing":missing,"confidence":conf,"formula":ftxt,
                                              "direction_confidence":dconf,"direction_seen":dseen,
                                              "structural_direction":structural_direction,"recovery_route":recovery_route,
                                              "sparse_outlier_certificate":sparse_cert if sparse_ok else None,
                                              "examples":target_examples})
            # Independent equations that converge on the same replacement are a stronger direction anchor
            # than JSON object key order. Count distinct certified formulas per exact proposed value.
            votes=defaultdict(set)
            for eq in equations:
                for i,o,exp in eq["missing"]:
                    new=canonical_number_like(exp,eq["examples"]); votes[(pointer(parts+[i,eq["target"]]),_jkey(new))].add(eq["formula"])
                for i,o,exp,_ in eq["violations"]:
                    new=canonical_number_like(exp,eq["examples"]); votes[(pointer(parts+[i,eq["target"]]),_jkey(new))].add(eq["formula"])
            for eq in equations:
                structural=eq["structural_direction"]
                r.relations.append(_rel("exact_arithmetic",parts,[eq["a"],eq["b"]],eq["target"],eq["confidence"],len(eq["support"]),
                    formula=eq["formula"],operator=eq["symbol"],direction_certified=structural,
                    direction_source="stable_object_key_order" if structural else "candidate_level_federation_required",
                    direction_confidence=round(eq["direction_confidence"],12),recovery_route=eq.get("recovery_route"),
                    sparse_outlier_certificate=eq.get("sparse_outlier_certificate")))
                for kind,items in (("missing",eq["missing"]),("violation",eq["violations"])):
                    for item in items:
                        i,o,exp=item[:3]
                        path=pointer(parts+[i,eq["target"]]); new=canonical_number_like(exp,eq["examples"])
                        agreeing=sorted(votes[(path,_jkey(new))])
                        multi=len(agreeing)>=2
                        direction_certified=structural or multi
                        source="stable_object_key_order" if structural else ("multi_equation_consensus" if multi else "cross_family_required")
                        meta={"formula":eq["formula"],"support":len(eq["support"]),"relation_kind":"exact_arithmetic","operator":eq["symbol"],
                              "direction_certified":direction_certified,"direction_source":source,
                              "direction_confidence":round(eq["direction_confidence"],12),"direction_seen":eq["direction_seen"],
                              "agreeing_formulas":agreeing,"requires_cross_family":not direction_certified,
                              "recovery_route":eq.get("recovery_route")}
                        if kind=="missing": meta["add_if_missing"]=eq["target"] not in o
                        code="missing_exact_value" if kind=="missing" else "exact_arithmetic_violation"
                        msg=(f"{eq['target']} is exactly determined by {eq['a']}{eq['symbol']}{eq['b']}." if kind=="missing" else
                             f"{eq['target']} violates exact invariant {eq['target']}={eq['a']}{eq['symbol']}{eq['b']}.")
                        r.issues.append(Issue(self.name,code,path,msg,"warning",True,meta))
                        evidence=tuple(agreeing) if multi else (eq["formula"],)
                        r.candidates.append(cand(self.name,path,o.get(eq["target"]),new,
                            "Reconstruct exact arithmetic invariant." if kind=="missing" else "Restore exact arithmetic invariant.",
                            confidence=eq["confidence"],evidence=evidence,metadata=meta))
        return r

def _parse_iso(v:Any):
    if not isinstance(v,str) or len(v)<8: return None
    s=v.strip()
    try:
        if s.endswith("Z"): s=s[:-1]+"+00:00"
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _iso_like(dt:datetime, example:str|None):
    if example and example.endswith("Z") and dt.utcoffset()==timedelta(0): return dt.isoformat().replace("+00:00","Z")
    if example and "T" not in example and dt.hour==0 and dt.minute==0 and dt.second==0 and dt.microsecond==0: return dt.date().isoformat()
    return dt.isoformat()


class TemporalAnalyzer:
    name="temporal"
    def analyze(self,root,config):
        r=AnalysisResult()
        for parts,arr in object_arrays(root):
            keys=sorted(set().union(*(o.keys() for o in arr)))
            temporal=[k for k in keys if sum(_parse_iso(o.get(k)) is not None for o in arr)>=config.min_support]
            for start in temporal:
                for end in temporal:
                    if start==end: continue
                    deltas=[]; observed=[]
                    for i,o in enumerate(arr):
                        a,b=_parse_iso(o.get(start)),_parse_iso(o.get(end))
                        if a is None or b is None: continue
                        try: d=b-a
                        except TypeError: continue
                        deltas.append(d.total_seconds()); observed.append((i,o,a,b))
                    if len(deltas)<config.min_support: continue
                    counts=Counter(deltas); sec,n=counts.most_common(1)[0]; conf=n/len(deltas)
                    if conf<config.temporal_confidence: continue
                    # Avoid duplicate reverse relation; prefer positive/zero duration orientation.
                    if sec<0: continue
                    r.relations.append(_rel("temporal_delta",parts,[start],end,conf,n,seconds=sec,formula=f"{end}={start}+{sec}s"))
                    evidence=(f"TIME:{end}={start}+{sec}s",)
                    examples=[o.get(end) for o in arr if _parse_iso(o.get(end)) is not None]
                    for i,o in enumerate(arr):
                        a=_parse_iso(o.get(start)); b=_parse_iso(o.get(end))
                        if a is None: continue
                        exp=a+timedelta(seconds=sec); new=_iso_like(exp,examples[0] if examples else None)
                        meta={"start":start,"end":end,"seconds":sec,"support":n,"relation_kind":"temporal_delta"}
                        if b is None:
                            if end in o and o[end] is not None: continue
                            path=pointer(parts+[i,end]); meta["add_if_missing"]=end not in o
                            r.issues.append(Issue(self.name,"missing_temporal_endpoint",path,"Temporal endpoint is determined by a stable exact delta.","warning",True,meta))
                            r.candidates.append(cand(self.name,path,o.get(end),new,"Reconstruct stable temporal delta.",confidence=conf,evidence=evidence,metadata=meta))
                        else:
                            try: same=(b-a).total_seconds()==sec
                            except TypeError: same=False
                            if not same:
                                path=pointer(parts+[i,end])
                                r.issues.append(Issue(self.name,"temporal_delta_violation",path,"Temporal endpoint violates a stable exact delta.","warning",True,meta))
                                r.candidates.append(cand(self.name,path,o[end],new,"Restore stable temporal delta.",confidence=conf,evidence=evidence,metadata=meta))
        return r


class SequentialAnalyzer:
    name="sequential"
    def analyze(self,root,config):
        r=AnalysisResult()
        for parts,arr in object_arrays(root):
            keys=sorted(set().union(*(o.keys() for o in arr)))
            for key in keys:
                vals=[]
                for o in arr:
                    v=o.get(key)
                    vals.append(v if isinstance(v,int) and not isinstance(v,bool) else None)
                diffs=[]
                for i in range(len(vals)-1):
                    if vals[i] is not None and vals[i+1] is not None: diffs.append(vals[i+1]-vals[i])
                if len(diffs)<max(2,config.min_support-1): continue
                step,n=Counter(diffs).most_common(1)[0]
                disrupted=len(diffs)-n
                effective_anomalies=(disrupted+1)//2
                conf=n/max(1,n+effective_anomalies)
                if conf<config.sequential_confidence or step==0: continue
                r.relations.append(_rel("sequence_step",parts,[key],key,conf,n,step=step))
                for i in range(1,len(arr)-1):
                    prev,nxt=vals[i-1],vals[i+1]
                    if prev is None or nxt is None: continue
                    expected=prev+step
                    if nxt-step!=expected: continue  # independent witness from both sides
                    old=vals[i]
                    if old==expected: continue
                    path=pointer(parts+[i,key]); meta={"field":key,"step":step,"left":prev,"right":nxt,"relation_kind":"sequence_step"}
                    if old is None:
                        meta["add_if_missing"]=key not in arr[i]
                        r.issues.append(Issue(self.name,"missing_sequence_value",path,"Value is fixed by matching left/right sequence witnesses.","warning",True,meta))
                        r.candidates.append(cand(self.name,path,arr[i].get(key),expected,"Reconstruct exact sequence value from both neighbors.",confidence=conf,evidence=(f"SEQ:{key}:step={step}:left",f"SEQ:{key}:step={step}:right"),metadata=meta))
                    else:
                        r.issues.append(Issue(self.name,"sequence_violation",path,"Value violates a stable sequence and both neighbors agree on the repair.","warning",True,meta))
                        r.candidates.append(cand(self.name,path,arr[i][key],expected,"Restore exact sequence value from both neighbors.",confidence=conf,evidence=(f"SEQ:{key}:step={step}:left",f"SEQ:{key}:step={step}:right"),metadata=meta))
        return r



class ConservationAnalyzer:
    """Exact conservation and local↔aggregate bridge discovery.

    Inferred laws may diagnose symmetric conservation failures without choosing a side.
    Mutations are emitted only when the aggregate direction is materially anchored or an
    authoritative conservation rule declares the target side explicitly.
    """
    name="conservation"

    @staticmethod
    def _direction_witness(arr, source_field, target_field, threshold, min_support):
        seen=0; forward=0
        for o in arr:
            if not isinstance(o,dict) or source_field not in o or target_field not in o: continue
            keys=list(o.keys()); seen+=1
            if keys.index(source_field)<keys.index(target_field): forward+=1
        conf=forward/seen if seen else 0.0
        structural=seen>=min_support and conf>=threshold
        return structural,conf,seen

    @staticmethod
    def _child_fields(arr, limit):
        counts=Counter()
        for o in arr:
            if not isinstance(o,dict): continue
            for k,v in o.items():
                if isinstance(v,list) and all(isinstance(x,dict) for x in v): counts[k]+=1
        return [k for k,_ in counts.most_common(limit)]

    @staticmethod
    def _child_item_schema(arr, child_field, limit):
        key_counts=Counter(); numeric_counts=Counter(); scalar_counts=Counter(); values=defaultdict(set)
        for o in arr:
            items=o.get(child_field) if isinstance(o,dict) else None
            if not isinstance(items,list): continue
            for item in items:
                if not isinstance(item,dict): continue
                for k,v in item.items():
                    key_counts[k]+=1
                    if decimal_of(v) is not None: numeric_counts[k]+=1
                    if _scalar(v):
                        scalar_counts[k]+=1
                        jk=_jkey(v)
                        if jk is not None and len(values[k])<64: values[k].add(jk)
        numeric=[k for k,_ in numeric_counts.most_common(limit)]
        keys=[k for k,_ in scalar_counts.most_common(limit) if len(values[k])>=2]
        return keys,numeric

    @staticmethod
    def _serialize_residue(residue):
        if isinstance(residue,Decimal): return format(residue,"f")
        if isinstance(residue,dict): return {str(k):str(v) for k,v in residue.items()}
        return residue

    def _authoritative(self, root, config, r):
        rules=[]
        for raw in getattr(config,"conservation_rules",()) or ():
            if not isinstance(raw,dict): continue
            doc=raw.get("document"); cur=getattr(config,"conservation_document",None)
            if doc is not None and doc not in {cur,"@single" if cur is None else cur}: continue
            if doc=="@single" and cur is not None: continue
            if raw.get("source") not in (None,"authoritative"): continue
            rule=dict(raw); rule.setdefault("rule_id",stable_conservation_id(rule)); rules.append(rule)
        if not rules: return
        arrays={pointer(parts):(parts,arr) for parts,arr in object_arrays(root)}
        allowed={"aggregate_sum","aggregate_count","balance","multiset_balance"}
        for rule in rules:
            rid=str(rule["rule_id"]); kind=rule.get("kind"); scope=str(rule.get("array_path",""))
            if kind not in allowed:
                r.issues.append(Issue(self.name,"conservation_rule_invalid",scope,f"Unknown conservation rule kind {kind!r}.","error",False,
                                      {"relation_kind":"conservation_rule","conservation_rule_id":rid,"conservation_source":"authoritative"}))
                continue
            if scope not in arrays:
                r.issues.append(Issue(self.name,"conservation_rule_scope_missing",scope,
                                      f"Authoritative conservation scope {scope!r} does not resolve to a repeated object array.","error",False,
                                      {"relation_kind":"conservation_rule","conservation_rule_id":rid,"conservation_source":"authoritative"}))
                continue
            parts,arr=arrays[scope]
            inputs=[]; output=None
            if kind in {"aggregate_sum","aggregate_count"}:
                inputs=[str(rule.get("items_field"))]; output=rule.get("target")
            elif kind=="balance":
                inputs=[str(t.get("field")) for t in rule.get("terms",[]) if isinstance(t,dict) and t.get("field")]; output=rule.get("target")
            else:
                inputs=[str(rule.get("left_field")),str(rule.get("right_field"))]; output=rule.get("target_side")
            rel=_rel(f"{kind}_authoritative",parts,inputs,output,1.0,len(arr),conservation_rule_id=rid,
                     conservation_source="authoritative",bridge_kind="local_to_aggregate" if kind.startswith("aggregate_") else "conservation",
                     rule=rule,direction_certified=True,direction_source="authoritative_rule")
            r.relations.append(rel)
            for i,row in enumerate(arr):
                ev=evaluate_conservation_rule(row,rule)
                if ev.get("status") is not False: continue
                patch=conservation_rule_patch(row,rule)
                base=parts+[i]
                if patch and "path_parts" in patch: path=pointer(base+list(patch["path_parts"]))
                elif patch: path=pointer(base+[patch["path_field"]])
                else: path=pointer(base)
                meta={"conservation_rule_id":rid,"relation_id":rel["relation_id"],"relation_kind":rel["kind"],
                      "conservation_source":"authoritative","residue":self._serialize_residue(ev.get("residue")),
                      "direction_certified":True,"direction_source":"authoritative_rule"}
                repairable=patch is not None
                r.issues.append(Issue(self.name,"conservation_violation",path,f"Record violates authoritative conservation rule {rid} ({kind}).",
                                      "warning",repairable,meta))
                if patch:
                    old=patch["old_value"]; new=patch["new_value"]; cmeta=dict(meta); cmeta["add_if_missing"]=bool(patch.get("add_if_missing"))
                    r.candidates.append(cand(self.name,path,old,new,"Restore authoritative exact conservation law.",confidence=1.0,
                                             evidence=(f"CONSERVATION:{rid}",),metadata=cmeta))

    def _inferred_aggregates(self, root, config, r):
        threshold=float(getattr(config,"conservation_confidence",0.95)); min_support=max(config.min_support,int(getattr(config,"conservation_min_support",config.min_support)))
        min_distinct=max(2,int(getattr(config,"conservation_min_distinct_aggregates",2)))
        dthreshold=float(getattr(config,"conservation_direction_confidence",0.90))
        child_limit=max(1,int(getattr(config,"conservation_max_child_fields",8)))
        item_limit=max(1,int(getattr(config,"conservation_max_item_fields",8)))
        for parts,arr in object_arrays(root):
            keys=sorted(set().union(*(o.keys() for o in arr)))
            parent_numeric=[k for k in keys if sum(decimal_of(o.get(k)) is not None for o in arr)>=min_support][:config.max_numeric_fields]
            children=self._child_fields(arr,child_limit)
            for child in children:
                _,child_numeric=self._child_item_schema(arr,child,item_limit)
                for value_field in child_numeric:
                    observations=[]; missing=[]
                    for i,o in enumerate(arr):
                        exp=sum_child_values(o,child,value_field)
                        if exp is None: continue
                        actual=decimal_of(o.get(next(iter(parent_numeric),"__none__"))) if False else None
                        observations.append((i,o,exp))
                    if len(observations)<min_support: continue
                    if len({format(x[2],"f") for x in observations})<min_distinct: continue
                    for target in parent_numeric:
                        support=[]; violations=[]; target_missing=[]; examples=[]
                        for i,o,exp in observations:
                            dt=decimal_of(o.get(target))
                            if dt is None:
                                target_missing.append((i,o,exp)); continue
                            examples.append(o.get(target))
                            (support if dt==exp else violations).append((i,o,exp,dt))
                        total=len(support)+len(violations)
                        if total<min_support: continue
                        conf=len(support)/total
                        if conf<threshold: continue
                        structural,dconf,dseen=self._direction_witness(arr,child,target,dthreshold,min_support)
                        name_hint=aggregate_target_hint(target,"sum")
                        direction=structural or name_hint
                        source="aggregate_target_name" if name_hint else ("parent_key_order" if structural else "cross_family_required")
                        rel=_rel("aggregate_sum",parts,[f"{child}[*].{value_field}"],target,conf,len(support),items_field=child,value_field=value_field,
                                 bridge_kind="local_to_aggregate",direction_certified=direction,direction_source=source,
                                 direction_confidence=round(dconf,12),direction_seen=dseen)
                        r.relations.append(rel)
                        for kind,items in (("violation",violations),("missing",target_missing)):
                            for item in items:
                                i,o,exp=item[:3]; path=pointer(parts+[i,target]); old=o.get(target)
                                meta={"relation_id":rel["relation_id"],"relation_kind":"aggregate_sum","items_field":child,"value_field":value_field,
                                      "target":target,"bridge_kind":"local_to_aggregate","direction_certified":direction,"direction_source":source,
                                      "requires_cross_family":not direction,"support":len(support)}
                                if kind=="missing": meta["add_if_missing"]=target not in o
                                r.issues.append(Issue(self.name,"aggregate_sum_violation" if kind=="violation" else "aggregate_sum_missing",path,
                                    f"Parent aggregate {target!r} does not equal the exact sum of {child}[*].{value_field}.","warning",True,meta))
                                new=canonical_number_like(exp,examples)
                                r.candidates.append(cand(self.name,path,old,new,"Restore exact local-to-aggregate sum bridge.",confidence=conf,
                                                         evidence=(f"AGG_SUM:{child}[*].{value_field}->{target}",),metadata=meta))
                # Count bridge.
                count_obs=[(i,o,len(o[child])) for i,o in enumerate(arr) if isinstance(o.get(child),list)]
                if len(count_obs)>=min_support:
                    for target in parent_numeric:
                        support=[]; violations=[]; missing=[]; examples=[]
                        for i,o,exp in count_obs:
                            dt=decimal_of(o.get(target))
                            if dt is None: missing.append((i,o,exp)); continue
                            examples.append(o.get(target)); (support if dt==Decimal(exp) else violations).append((i,o,exp,dt))
                        total=len(support)+len(violations)
                        if total<min_support: continue
                        conf=len(support)/total
                        if conf<threshold: continue
                        structural,dconf,dseen=self._direction_witness(arr,child,target,dthreshold,min_support)
                        name_hint=aggregate_target_hint(target,"count"); direction=structural or name_hint
                        if len({x[2] for x in count_obs})<min_distinct and not name_hint:
                            continue
                        source="aggregate_target_name" if name_hint else ("parent_key_order" if structural else "cross_family_required")
                        rel=_rel("aggregate_count",parts,[f"len({child})"],target,conf,len(support),items_field=child,bridge_kind="local_to_aggregate",
                                 direction_certified=direction,direction_source=source,direction_confidence=round(dconf,12),direction_seen=dseen)
                        r.relations.append(rel)
                        for kind,items in (("violation",violations),("missing",missing)):
                            for item in items:
                                i,o,exp=item[:3]; path=pointer(parts+[i,target]); old=o.get(target)
                                meta={"relation_id":rel["relation_id"],"relation_kind":"aggregate_count","items_field":child,"target":target,
                                      "bridge_kind":"local_to_aggregate","direction_certified":direction,"direction_source":source,
                                      "requires_cross_family":not direction,"support":len(support)}
                                if kind=="missing": meta["add_if_missing"]=target not in o
                                r.issues.append(Issue(self.name,"aggregate_count_violation" if kind=="violation" else "aggregate_count_missing",path,
                                    f"Parent count {target!r} does not equal len({child}).","warning",True,meta))
                                new=canonical_number_like(Decimal(exp),examples)
                                r.candidates.append(cand(self.name,path,old,new,"Restore exact local-to-aggregate count bridge.",confidence=conf,
                                                         evidence=(f"AGG_COUNT:len({child})->{target}",),metadata=meta))

    def _inferred_scalar_balances(self, root, config, r):
        threshold=float(getattr(config,"conservation_confidence",0.95)); min_support=max(config.min_support,int(getattr(config,"conservation_min_support",config.min_support)))
        max_fields=min(8,int(getattr(config,"conservation_max_balance_fields",8)))
        for parts,arr in object_arrays(root):
            keys=sorted(set().union(*(o.keys() for o in arr)))
            numeric=[k for k in keys if sum(decimal_of(o.get(k)) is not None for o in arr)>=min_support][:max_fields]
            for quartet in combinations(numeric,4):
                a,b,c,d=quartet
                pairings=((a,b,c,d),(a,c,b,d),(a,d,b,c))
                for x1,x2,y1,y2 in pairings:
                    support=[]; violations=[]; signatures=set()
                    for i,o in enumerate(arr):
                        vals=[decimal_of(o.get(f)) for f in (x1,x2,y1,y2)]
                        if any(v is None for v in vals): continue
                        left=vals[0]+vals[1]; right=vals[2]+vals[3]; signatures.add((format(left,"f"),format(right,"f")))
                        (support if left==right else violations).append((i,o,left-right))
                    total=len(support)+len(violations)
                    if total<min_support or len(signatures)<2: continue
                    conf=len(support)/total
                    if conf<threshold: continue
                    formula=f"{x1}+{x2}={y1}+{y2}"
                    rel=_rel("scalar_conservation_balance",parts,[x1,x2,y1,y2],None,conf,len(support),formula=formula,
                             bridge_kind="same_level_balance",direction_certified=False,direction_source="symmetric_conservation")
                    r.relations.append(rel)
                    for i,o,residue in violations:
                        meta={"relation_id":rel["relation_id"],"relation_kind":"scalar_conservation_balance","formula":formula,
                              "residue":format(residue,"f"),"direction_certified":False,"direction_source":"symmetric_conservation"}
                        r.issues.append(Issue(self.name,"scalar_conservation_violation",pointer(parts+[i]),
                                              f"Record violates exact conservation balance {formula}; the failing side is not identifiable from this law alone.",
                                              "warning",False,meta))

    def _inferred_multisets(self, root, config, r):
        threshold=float(getattr(config,"multiset_confidence",getattr(config,"conservation_confidence",0.95)))
        min_support=max(config.min_support,int(getattr(config,"multiset_min_support",getattr(config,"conservation_min_support",config.min_support))))
        child_limit=max(1,int(getattr(config,"conservation_max_child_fields",8))); item_limit=max(1,int(getattr(config,"conservation_max_item_fields",8)))
        for parts,arr in object_arrays(root):
            children=self._child_fields(arr,child_limit)
            schemas={c:self._child_item_schema(arr,c,item_limit) for c in children}
            for left,right in combinations(children,2):
                lkeys,lnum=schemas[left]; rkeys,rnum=schemas[right]
                for key_field in sorted(set(lkeys)&set(rkeys)):
                    for qty_field in sorted(set(lnum)&set(rnum)):
                        if key_field==qty_field: continue
                        support=[]; violations=[]; distinct=set()
                        for i,o in enumerate(arr):
                            lm=multiset_map(o.get(left),key_field,qty_field); rm=multiset_map(o.get(right),key_field,qty_field)
                            if lm is None or rm is None: continue
                            ident=json.dumps({k:format(v,'f') for k,v in lm.items()},sort_keys=True,separators=(",",":")); distinct.add(ident)
                            residue=multiset_residue(lm,rm)
                            (support if not residue else violations).append((i,o,residue))
                        total=len(support)+len(violations)
                        if total<min_support or len(distinct)<2: continue
                        conf=len(support)/total
                        if conf<threshold: continue
                        rel=_rel("multiset_conservation",parts,[left,right],None,conf,len(support),left_field=left,right_field=right,
                                 key_field=key_field,quantity_field=qty_field,bridge_kind="multiset_balance",
                                 direction_certified=False,direction_source="symmetric_multiset")
                        r.relations.append(rel)
                        for i,o,residue in violations:
                            meta={"relation_id":rel["relation_id"],"relation_kind":"multiset_conservation","left_field":left,"right_field":right,
                                  "key_field":key_field,"quantity_field":qty_field,"residue":{k:format(v,'f') for k,v in residue.items()},
                                  "direction_certified":False,"direction_source":"symmetric_multiset"}
                            r.issues.append(Issue(self.name,"multiset_conservation_violation",pointer(parts+[i]),
                                f"Multiset quantities are not conserved between {left!r} and {right!r}; no target side is inferred.","warning",False,meta))

    def analyze(self,root,config):
        r=AnalysisResult()
        self._authoritative(root,config,r)
        self._inferred_aggregates(root,config,r)
        self._inferred_scalar_balances(root,config,r)
        self._inferred_multisets(root,config,r)
        return r


class LogicExactAnalyzer:
    """Exact finite logic layer for repeated JSON object populations.

    Two sources are intentionally separated:
      * inferred rules: conservative, high-support boolean invariants discovered from data;
      * authoritative rules: explicit constraints supplied through RepairConfig.logic_rules.

    The analyzer never treats SAT as truth of the data. SAT only certifies that the declared
    finite rule system is internally satisfiable. Current-object violations are measured separately.
    """
    name="logic_exact"

    @staticmethod
    def _field_names(rule):
        out=[]
        def add_pred(p):
            if isinstance(p,dict) and isinstance(p.get("field"),str): out.append(p["field"])
        if rule.get("kind")=="implies":
            ants=rule.get("if",[]); ants=[ants] if isinstance(ants,dict) else ants
            for p in ants if isinstance(ants,list) else []: add_pred(p)
            add_pred(rule.get("then"))
        else:
            for p in rule.get("items",[]) if isinstance(rule.get("items",[]),list) else []: add_pred(p)
        return sorted(set(out))

    @staticmethod
    def _candidate_with_meta(c, **extra):
        meta=dict(c.metadata); meta.update(extra)
        return Candidate(c.candidate_id,c.analyzer,c.operation,c.path,c.old_value,c.new_value,c.reason,c.confidence,c.cost,c.evidence,meta)

    def _emit_rule(self, r, parts, arr, rule, confidence, support, source, sat_cert):
        rid=str(rule.get("rule_id") or stable_rule_id(rule, "logic"))
        fields=self._field_names(rule)
        output=(rule.get("then") or {}).get("field") if rule.get("kind")=="implies" and isinstance(rule.get("then"),dict) else None
        relation=_rel("logic_exact",parts,fields,output,confidence,support,
                      logic_rule_id=rid,logic_kind=rule.get("kind"),logic_source=source,
                      sat_status=sat_cert.get("status"),sat_certificate=sat_cert,rule=rule)
        r.relations.append(relation)
        for i,row in enumerate(arr):
            if not isinstance(row,dict): continue
            verdict=evaluate_rule(row,rule)
            if verdict is not False: continue
            base=pointer(parts+[i])
            cands=repair_candidates_for_rule(row,rule,base,analyzer=self.name,confidence=confidence)
            cands=[self._candidate_with_meta(c,relation_id=relation["relation_id"],logic_rule_id=rid,
                                             logic_source=source,logic_kind=rule.get("kind")) for c in cands]
            issue_path=cands[0].path if rule.get("kind")=="implies" and len(cands)==1 else base
            meta={"logic_rule_id":rid,"logic_kind":rule.get("kind"),"logic_source":source,
                  "relation_id":relation["relation_id"],"relation_kind":"logic_exact",
                  "sat_status":sat_cert.get("status"),"alternative_patch_count":len(cands)}
            r.issues.append(Issue(self.name,"logical_constraint_violation",issue_path,
                                  f"Record violates exact logical rule {rid} ({rule.get('kind')}).",
                                  "warning",bool(cands),meta))
            r.candidates.extend(cands)

    def _authoritative(self, root, config, r):
        rules=[]
        for raw in getattr(config,"logic_rules",()) or ():
            if not isinstance(raw,dict): continue
            doc=raw.get("document")
            cur=getattr(config,"logic_document",None)
            if doc is not None and doc not in {cur,"@single" if cur is None else cur}:
                continue
            if doc=="@single" and cur is not None: continue
            if raw.get("source") not in (None,"authoritative"): continue
            rule=dict(raw); rule.setdefault("rule_id",stable_rule_id(rule,"logic")); rules.append(rule)
        if not rules: return
        arrays={pointer(parts):(parts,arr) for parts,arr in object_arrays(root)}
        by_scope=defaultdict(list)
        for rule in rules:
            scope=str(rule.get("array_path","")); by_scope[scope].append(rule)
        for scope, scoped in sorted(by_scope.items()):
            if scope not in arrays:
                r.issues.append(Issue(self.name,"logic_rule_scope_missing",scope,
                                      f"Authoritative logic scope {scope!r} does not resolve to a repeated object array.",
                                      "error",False,{"relation_kind":"logic_exact","logic_source":"authoritative","rule_ids":[x["rule_id"] for x in scoped]}))
                continue
            parts,arr=arrays[scope]
            cert=rule_system_certificate(scoped)
            # One system relation records the SAT/UNSAT gate independently from row violations.
            system_payload={"kind":"logic_rule_system","array_path":scope,"inputs":sorted(set(f for x in scoped for f in self._field_names(x))),
                            "output":None,"confidence":1.0,"support":len(arr),"logic_source":"authoritative",
                            "rule_ids":[x["rule_id"] for x in scoped],"sat_status":cert["status"],"sat_certificate":cert}
            identity={k:v for k,v in system_payload.items() if k not in {"confidence","support","sat_certificate"}}
            system_payload["relation_id"]=hashlib.sha1(json.dumps(identity,sort_keys=True,default=str,separators=(",",":")).encode()).hexdigest()[:20]
            r.relations.append(system_payload)
            if cert["status"]=="UNSAT":
                r.issues.append(Issue(self.name,"logical_rule_system_unsat",scope,
                                      "Authoritative boolean logic rules are jointly UNSAT; no data mutation is legal until the rule set is revised.",
                                      "error",False,{"relation_kind":"logic_rule_system","relation_id":system_payload["relation_id"],
                                                     "sat_certificate":cert,"unsat_core_rule_ids":cert.get("unsat_core_rule_ids",[])}))
                continue
            for rule in scoped:
                self._emit_rule(r,parts,arr,rule,1.0,len(arr),"authoritative",cert)

    def _inferred(self, root, config, r):
        max_fields=max(2,int(getattr(config,"logic_max_fields",8)))
        max_group=max(2,int(getattr(config,"logic_max_group_size",4)))
        min_member=max(1,int(getattr(config,"logic_min_member_support",2)))
        threshold=float(getattr(config,"logic_confidence",0.95))
        min_support=max(config.min_support,int(getattr(config,"logic_min_support",config.min_support)))
        for parts,arr in object_arrays(root):
            all_keys=sorted(set().union(*(o.keys() for o in arr)))[:max_fields]
            bool_fields=[]
            for key in all_keys:
                vals=[o.get(key) for o in arr if isinstance(o.get(key),bool)]
                if len(vals)>=min_support and sum(v is True for v in vals)>=min_member and sum(v is False for v in vals)>=min_member:
                    bool_fields.append(key)
            # Exact-one boolean groups. Require every alternative to be materially exercised.
            for k in range(2,min(max_group,len(bool_fields))+1):
                for fields in combinations(bool_fields,k):
                    rows=[o for o in arr if all(isinstance(o.get(f),bool) for f in fields)]
                    if len(rows)<min_support: continue
                    sat=sum(1 for o in rows if sum(bool(o[f]) for f in fields)==1)
                    conf=sat/len(rows)
                    if conf<threshold: continue
                    if any(sum(1 for o in rows if o[f] is True)<min_member for f in fields): continue
                    rule={"kind":"exactly_one","array_path":pointer(parts),"items":[{"field":f,"equals":True} for f in fields],"source":"inferred"}
                    rule["rule_id"]=stable_rule_id(rule,"logic")
                    cert=rule_system_certificate([rule])
                    self._emit_rule(r,parts,arr,rule,conf,sat,"inferred",cert)
            # Multivariate conjunctive implication: (a=True AND b=True) -> target=bool.
            # Target must vary globally; otherwise a constant field would masquerade as a causal rule.
            for target in bool_fields:
                target_vals=[o[target] for o in arr if isinstance(o.get(target),bool)]
                if len(set(target_vals))<2: continue
                antecedents=[f for f in bool_fields if f!=target]
                for a,b in combinations(antecedents,2):
                    rows=[o for o in arr if o.get(a) is True and o.get(b) is True and isinstance(o.get(target),bool)]
                    if len(rows)<min_support: continue
                    ctr=Counter(o[target] for o in rows); expected,n=ctr.most_common(1)[0]; conf=n/len(rows)
                    if conf<threshold: continue
                    rule={"kind":"implies","array_path":pointer(parts),"if":[{"field":a,"equals":True},{"field":b,"equals":True}],
                          "then":{"field":target,"equals":expected},"source":"inferred"}
                    rule["rule_id"]=stable_rule_id(rule,"logic")
                    cert=rule_system_certificate([rule])
                    self._emit_rule(r,parts,arr,rule,conf,n,"inferred",cert)

    def analyze(self,root,config):
        r=AnalysisResult()
        self._authoritative(root,config,r)
        self._inferred(root,config,r)
        return r




class ConstraintBridgeAnalyzer:
    name="constraint_bridge"
    def analyze(self,root,config):
        from .linear_exact import analyze_constraints
        from .schema_bridge import analyze_schema
        a=analyze_constraints(root,config); b=analyze_schema(root,config)
        a.issues.extend(b.issues); a.candidates.extend(b.candidates); a.relations.extend(b.relations)
        return a


class MomentDistributionAnalyzer:
    name="moments"
    def analyze(self,root,config):
        from .moments import analyze_moments
        return analyze_moments(root,config)

class SystemGraphStateAnalyzer:
    name="system_graph_state"
    def analyze(self,root,config):
        from .system_graph import analyze_system_rules
        return analyze_system_rules(root,config)

class StructuralMigrationAnalyzer:
    name="structural_migration"
    def analyze(self,root,config):
        from .structural import analyze_structural_migrations
        return analyze_structural_migrations(root,config)

SENSITIVE_ANALYZERS=(
    SchemaStructureAnalyzer(),
    StructuralMigrationAnalyzer(),
    TypePatternAnalyzer(),
    EnumDomainAnalyzer(),
    FunctionalRelationAnalyzer(),
    ScopedFunctionalRelationAnalyzer(),
    ExactArithmeticAnalyzer(),
    TemporalAnalyzer(),
)

ORDINARY_ANALYZERS=(
    ConstraintBridgeAnalyzer(),
    MomentDistributionAnalyzer(),
    SystemGraphStateAnalyzer(),
    IdentifierReferenceAnalyzer(),
    ConservationAnalyzer(),
    LogicExactAnalyzer(),
    SequentialAnalyzer(),
)

DEFAULT_ANALYZERS=SENSITIVE_ANALYZERS+ORDINARY_ANALYZERS


def analyze_all(root,config):
    from .modal import modal_analyze, recursive_morphology
    # All analyzer families inspect the same sovereign object. Cache only this pure
    # structural projection for the duration of one analyze_all call; ContextVar
    # preserves nested/threaded isolation and never leaks a document across calls.
    token=_OBJECT_ARRAY_SCAN.set((root,_compute_object_arrays(root)))
    try:
        out=modal_analyze(root,config,object_arrays,list(SENSITIVE_ANALYZERS),list(ORDINARY_ANALYZERS))
        morph=recursive_morphology(root,config)
        out.issues.extend(morph.issues); out.candidates.extend(morph.candidates); out.relations.extend(morph.relations)
        # relation de-duplication by stable relation_id
        uniq={x["relation_id"]:x for x in out.relations}
        out.relations=list(uniq.values())
        return out
    finally:
        _OBJECT_ARRAY_SCAN.reset(token)
