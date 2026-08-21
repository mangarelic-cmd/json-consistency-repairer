from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
from typing import Any
import hashlib
import json

from .models import AnalysisResult, Candidate, Issue, digest
from .jsonpatch_exact import apply_candidate

_NUMERIC_KEYS=("minimum","exclusiveMinimum","maximum","exclusiveMaximum","multipleOf")
_SIZE_PAIRS=(("minLength","maxLength"),("minItems","maxItems"),("minProperties","maxProperties"),("minContains","maxContains"))
_SCHEMA_BOUNDARY_KEYS={
    "type","enum","const","minimum","exclusiveMinimum","maximum","exclusiveMaximum","multipleOf",
    "minLength","maxLength","pattern","minItems","maxItems","uniqueItems","contains","minContains","maxContains",
    "minProperties","maxProperties","required","dependentRequired","propertyNames","additionalProperties",
    "allOf","anyOf","oneOf","not","if","then","else","prefixItems","items","patternProperties","properties",
}
_DSL_BOUNDARY_KINDS={"required","type","enum","const","minimum","exclusiveMinimum","maximum","exclusiveMaximum","multipleOf","minLength","maxLength","pattern","minItems","maxItems","uniqueItems","minProperties","maxProperties"}


def _stable(prefix:str,payload:Any,n:int=24)->str:
    raw=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False,default=str).encode("utf-8")
    return f"{prefix}_{hashlib.sha256(raw).hexdigest()[:n]}"


def _q(v:Any)->Fraction|None:
    if isinstance(v,bool) or v is None:return None
    if isinstance(v,int):return Fraction(v)
    if isinstance(v,float):return Fraction(str(v))
    if isinstance(v,str):
        try:return Fraction(v)
        except Exception:return None
    return None



def _floor_frac(x:Fraction)->int:
    return x.numerator//x.denominator


def _ceil_frac(x:Fraction)->int:
    return -((-x.numerator)//x.denominator)


def project_numeric_boundary(value:Any,constraints:dict[str,Any],*,integer_domain:bool=False)->dict[str,Any]:
    """Project a numeric value onto the intersection of authoritative numeric boundaries.

    A projection is returned only when the minimum absolute-distance admissible value exists and
    is unique. Open real boundaries therefore abstain unless a discrete lattice (multipleOf or
    integer domain) makes the nearest admissible point material.
    """
    q=_q(value)
    if q is None:return {"status":"NON_NUMERIC","value":None,"distance":None}
    parsed={}
    for key in _NUMERIC_KEYS:
        if key in constraints:
            x=_q(constraints[key])
            if x is None:return {"status":"INVALID_BOUNDARY","keyword":key,"value":None,"distance":None}
            parsed[key]=x
    m=parsed.get("multipleOf")
    if m is not None and m<=0:return {"status":"INVALID_BOUNDARY","keyword":"multipleOf","value":None,"distance":None}
    def valid(x:Fraction)->bool:
        if integer_domain and x.denominator!=1:return False
        if "minimum" in parsed and x<parsed["minimum"]:return False
        if "exclusiveMinimum" in parsed and x<=parsed["exclusiveMinimum"]:return False
        if "maximum" in parsed and x>parsed["maximum"]:return False
        if "exclusiveMaximum" in parsed and x>=parsed["exclusiveMaximum"]:return False
        if m is not None and (x/m).denominator!=1:return False
        return True
    if valid(q):return {"status":"VALID","value":q,"distance":Fraction(0)}
    candidates:set[Fraction]=set()
    if m is not None:
        z=q/m; k0=_floor_frac(z); candidates.update({m*k0,m*(k0+1)})
        kmin=None;kmax=None
        if "minimum" in parsed:kmin=_ceil_frac(parsed["minimum"]/m)
        if "exclusiveMinimum" in parsed:
            x=parsed["exclusiveMinimum"]/m; k=minval=_floor_frac(x)+1
            kmin=k if kmin is None else max(kmin,k)
        if "maximum" in parsed:kmax=_floor_frac(parsed["maximum"]/m)
        if "exclusiveMaximum" in parsed:
            x=parsed["exclusiveMaximum"]/m; k=_ceil_frac(x)-1
            kmax=k if kmax is None else min(kmax,k)
        if kmin is not None:candidates.update({m*kmin,m*(kmin+1)})
        if kmax is not None:candidates.update({m*kmax,m*(kmax-1)})
        if kmin is not None and kmax is not None and kmin>kmax:return {"status":"EMPTY","value":None,"distance":None}
    elif integer_domain:
        # Integer domains are discrete even without multipleOf.
        candidates.update({Fraction(_floor_frac(q)),Fraction(_ceil_frac(q))})
        if "minimum" in parsed:candidates.add(Fraction(_ceil_frac(parsed["minimum"])))
        if "exclusiveMinimum" in parsed:candidates.add(Fraction(_floor_frac(parsed["exclusiveMinimum"])+1))
        if "maximum" in parsed:candidates.add(Fraction(_floor_frac(parsed["maximum"])))
        if "exclusiveMaximum" in parsed:candidates.add(Fraction(_ceil_frac(parsed["exclusiveMaximum"])-1))
    else:
        # A real open boundary has an infimum but no nearest admissible real point.
        if "exclusiveMinimum" in parsed and q<=parsed["exclusiveMinimum"]:return {"status":"NO_MINIMUM","value":None,"distance":None}
        if "exclusiveMaximum" in parsed and q>=parsed["exclusiveMaximum"]:return {"status":"NO_MINIMUM","value":None,"distance":None}
        x=q
        if "minimum" in parsed and x<parsed["minimum"]:x=parsed["minimum"]
        if "maximum" in parsed and x>parsed["maximum"]:x=parsed["maximum"]
        candidates.add(x)
    admissible=sorted((x for x in candidates if valid(x)),key=lambda x:(abs(x-q),x))
    if not admissible:return {"status":"EMPTY","value":None,"distance":None}
    d=abs(admissible[0]-q); nearest=[x for x in admissible if abs(x-q)==d]
    if len(nearest)!=1:return {"status":"AMBIGUOUS","value":None,"distance":d,"nearest":[str(x) for x in nearest]}
    return {"status":"UNIQUE","value":nearest[0],"distance":d,"nearest":[str(nearest[0])]}

def _schema_contracts(schema:Any,path:str="",lineage:tuple[str,...]=())->list[dict[str,Any]]:
    if isinstance(schema,bool):
        return [{"boundary_id":_stable("bound",[path,lineage,"boolean",schema]),"source":"json_schema","path_pattern":path,
                 "lineage":list(lineage),"constraints":{"boolean_schema":schema},"conditional":bool(lineage)}]
    if not isinstance(schema,dict):return []
    constraints={k:deepcopy(v) for k,v in schema.items() if k in _SCHEMA_BOUNDARY_KEYS and k not in {"properties","patternProperties","prefixItems","items","allOf","anyOf","oneOf","not","if","then","else","contains"}}
    out=[]
    if constraints:
        payload=[path,lineage,constraints]
        out.append({"boundary_id":_stable("bound",payload),"source":"json_schema","path_pattern":path,"lineage":list(lineage),
                    "constraints":constraints,"conditional":bool(lineage)})
    props=schema.get("properties")
    if isinstance(props,dict):
        for k,sub in sorted(props.items()):
            esc=str(k).replace("~","~0").replace("/","~1")
            out.extend(_schema_contracts(sub,path+"/"+esc,lineage))
    pats=schema.get("patternProperties")
    if isinstance(pats,dict):
        for pat,sub in sorted(pats.items()): out.extend(_schema_contracts(sub,path+"/{pattern:"+pat+"}",lineage+("patternProperties",)))
    pref=schema.get("prefixItems")
    if isinstance(pref,list):
        for i,sub in enumerate(pref): out.extend(_schema_contracts(sub,path+f"/{i}",lineage))
    items=schema.get("items")
    if isinstance(items,(dict,bool)): out.extend(_schema_contracts(items,path+"/*",lineage+("items",)))
    contains=schema.get("contains")
    if isinstance(contains,(dict,bool)): out.extend(_schema_contracts(contains,path+"/*",lineage+("contains",)))
    for key in ("allOf","anyOf","oneOf"):
        val=schema.get(key)
        if isinstance(val,list):
            for i,sub in enumerate(val): out.extend(_schema_contracts(sub,path,lineage+(f"{key}[{i}]",)))
    for key in ("not","if","then","else"):
        sub=schema.get(key)
        if isinstance(sub,(dict,bool)): out.extend(_schema_contracts(sub,path,lineage+(key,)))
    return out


def _dsl_contracts(rules:tuple[dict[str,Any],...]|list[dict[str,Any]])->list[dict[str,Any]]:
    groups={}
    for rule in rules or ():
        if not isinstance(rule,dict) or rule.get("kind") not in _DSL_BOUNDARY_KINDS:continue
        scope=str(rule.get("array_path","") or ""); field=rule.get("field")
        key=(scope,str(field) if field is not None else "")
        g=groups.setdefault(key,{"scope":scope,"field":field,"constraints":{},"rule_ids":[],"duplicate_conflicts":[]})
        kind=str(rule.get("kind")); val=deepcopy(rule.get("value") if "value" in rule else rule.get(kind))
        if kind=="required":val={"required":True,"default":deepcopy(rule.get("default")) if "default" in rule else None,"has_default":"default" in rule}
        elif kind=="type":val=deepcopy(rule.get("type"))
        elif kind=="enum":val=deepcopy(rule.get("values",[]))
        elif kind=="const":val=deepcopy(rule.get("value"))
        if kind in g["constraints"] and g["constraints"][kind]!=val:
            g["duplicate_conflicts"].append({"kind":kind,"a":deepcopy(g["constraints"][kind]),"b":deepcopy(val)})
        else:g["constraints"][kind]=val
        g["rule_ids"].append(str(rule.get("rule_id") or _stable("dslrule",rule)))
    out=[]
    for key,g in sorted(groups.items()):
        path=g["scope"]+("/*" if g["scope"] else "/*")
        if g["field"] is not None:path += "/"+str(g["field"]).replace("~","~0").replace("/","~1")
        payload=[g["scope"],g["field"],g["constraints"],g["rule_ids"]]
        out.append({"boundary_id":_stable("dslbound",payload),"source":"constraint_dsl","path_pattern":path,"lineage":[],
                    "constraints":g["constraints"],"conditional":False,"rule_ids":sorted(g["rule_ids"]),
                    "duplicate_conflicts":g["duplicate_conflicts"]})
    return out


def _conflicts_for(contract:dict[str,Any])->list[dict[str,Any]]:
    c=contract.get("constraints") or {}; out=[]
    for x in contract.get("duplicate_conflicts",[]) or []:
        out.append({"kind":"CONFLICTING_DUPLICATE_BOUND","keyword":x.get("kind"),"a":x.get("a"),"b":x.get("b")})
    lows=[]; highs=[]
    if "minimum" in c:
        q=_q(c["minimum"])
        if q is not None:lows.append((q,False,"minimum"))
    if "exclusiveMinimum" in c:
        q=_q(c["exclusiveMinimum"])
        if q is not None:lows.append((q,True,"exclusiveMinimum"))
    if "maximum" in c:
        q=_q(c["maximum"])
        if q is not None:highs.append((q,False,"maximum"))
    if "exclusiveMaximum" in c:
        q=_q(c["exclusiveMaximum"])
        if q is not None:highs.append((q,True,"exclusiveMaximum"))
    if lows and highs:
        lo=max(lows,key=lambda x:x[0]); hi=min(highs,key=lambda x:x[0])
        if lo[0]>hi[0] or (lo[0]==hi[0] and (lo[1] or hi[1])):
            out.append({"kind":"EMPTY_NUMERIC_INTERVAL","lower":{"value":str(lo[0]),"exclusive":lo[1],"keyword":lo[2]},
                        "upper":{"value":str(hi[0]),"exclusive":hi[1],"keyword":hi[2]}})
    if "multipleOf" in c:
        q=_q(c["multipleOf"])
        if q is None or q<=0: out.append({"kind":"INVALID_MULTIPLE_OF","value":c["multipleOf"]})
    for mn,mx in _SIZE_PAIRS:
        if mn in c and mx in c:
            try:
                if int(c[mn])>int(c[mx]):out.append({"kind":"EMPTY_CARDINALITY_INTERVAL","minimum_keyword":mn,"minimum":c[mn],"maximum_keyword":mx,"maximum":c[mx]})
            except Exception:out.append({"kind":"INVALID_CARDINALITY_BOUND","minimum_keyword":mn,"maximum_keyword":mx})
    return out


def compile_boundary_registry(schema:Any=None,constraint_rules:tuple[dict[str,Any],...]|list[dict[str,Any]]=())->dict[str,Any]:
    contracts=_schema_contracts(schema) + _dsl_contracts(constraint_rules)
    # semantic de-dup while preserving provenance contracts
    uniq={x["boundary_id"]:x for x in contracts}; contracts=[uniq[k] for k in sorted(uniq)]
    bob=[]
    for c in contracts:
        for conflict in _conflicts_for(c):
            bob.append({"bounds_of_bounds_id":_stable("bob",[c["boundary_id"],conflict]),"boundary_id":c["boundary_id"],
                        "path_pattern":c["path_pattern"],"conflict":conflict})
    return {"contract":"json-consistency-repair.boundary-registry.v1","boundary_count":len(contracts),
            "contracts":contracts,"bounds_of_bounds":{"conflict_count":len(bob),"conflicts":bob,
            "status":"CONFLICT" if bob else "COHERENT"}}


def _violation_key(i:Issue)->tuple[Any,...]:
    m=i.metadata or {}
    return (i.analyzer,i.code,i.path,m.get("schema_id"),m.get("rule_id"),m.get("schema_keyword"),m.get("boundary_id"))


def _boundary_issues(root:Any,config:Any)->list[Issue]:
    # Imported lazily to avoid schema_bridge <-> boundary import cycles.
    from .schema_bridge import analyze_schema
    from .linear_exact import analyze_simple_rules
    out=[]
    out.extend(analyze_schema(root,config).issues)
    out.extend(analyze_simple_rules(root,config).issues)
    reg=compile_boundary_registry(getattr(config,"json_schema",None),getattr(config,"constraint_rules",()))
    for x in reg["bounds_of_bounds"]["conflicts"]:
        out.append(Issue("boundary_firewall","bounds_of_bounds_conflict",x["path_pattern"],
                         "Authoritative boundary contract is internally inconsistent; mutation is blocked.","error",False,
                         {"boundary_id":x["boundary_id"],"bounds_of_bounds_id":x["bounds_of_bounds_id"],"conflict":x["conflict"]}))
    return out


def apply_boundary_firewall(root:Any,analysis:AnalysisResult,config:Any)->tuple[AnalysisResult,dict[str,Any]]:
    """Reject candidates that create a new authoritative boundary violation.

    Existing unrelated violations may persist during a local repair. What is forbidden is crossing
    an admissible boundary that was not already violated on the frozen snapshot.
    """
    registry=compile_boundary_registry(getattr(config,"json_schema",None),getattr(config,"constraint_rules",()))
    if not registry["boundary_count"]:
        return analysis,{"contract":"json-consistency-repair.boundary-firewall.v1","active":False,"checked":0,"rejected":0,
                        "boundary_registry":registry,"rejections":[]}
    if registry["bounds_of_bounds"]["conflict_count"]:
        blocked=AnalysisResult(list(analysis.issues),[],list(analysis.relations))
        for x in registry["bounds_of_bounds"]["conflicts"]:
            blocked.issues.append(Issue("boundary_firewall","bounds_of_bounds_conflict",x["path_pattern"],
                "Authoritative boundary contract is internally inconsistent; all mutations are blocked.","error",False,
                {"boundary_id":x["boundary_id"],"bounds_of_bounds_id":x["bounds_of_bounds_id"],"conflict":x["conflict"]}))
        return blocked,{"contract":"json-consistency-repair.boundary-firewall.v1","active":True,"checked":len(analysis.candidates),
                        "rejected":len(analysis.candidates),"reason":"BOUNDS_OF_BOUNDS_CONFLICT","boundary_registry":registry,
                        "rejections":[{"candidate_id":c.candidate_id,"reason":"BOUNDS_OF_BOUNDS_CONFLICT"} for c in analysis.candidates]}
    before={_violation_key(i) for i in _boundary_issues(root,config)}
    kept=[]; rejected=[]
    for c in analysis.candidates:
        trial=deepcopy(root)
        if not apply_candidate(trial,c):
            kept.append(c); continue
        after_issues=_boundary_issues(trial,config)
        novel=sorted({_violation_key(i) for i in after_issues}-before,key=str)
        if novel:
            rejected.append({"candidate_id":c.candidate_id,"path":c.path,"reason":"NEW_AUTHORITATIVE_BOUNDARY_VIOLATION","violations":[list(x) for x in novel]})
        else: kept.append(c)
    out=AnalysisResult(list(analysis.issues),kept,list(analysis.relations))
    return out,{"contract":"json-consistency-repair.boundary-firewall.v1","active":True,"checked":len(analysis.candidates),
                "rejected":len(rejected),"accepted":len(kept),"boundary_registry":registry,"rejections":rejected}


def boundary_summary(root:Any,analysis:AnalysisResult,config:Any,firewall:dict[str,Any]|None=None)->dict[str,Any]:
    reg=compile_boundary_registry(getattr(config,"json_schema",None),getattr(config,"constraint_rules",()))
    issues=[i for i in analysis.issues if i.analyzer in {"schema_bridge","constraint_dsl","boundary_firewall"}]
    return {"contract":"json-consistency-repair.boundary-summary.v1","registry":reg,
            "observed_boundary_violations":len(issues),"repairable_boundary_violations":sum(1 for i in issues if i.repairable),
            "boundary_issue_codes":dict(sorted(__import__('collections').Counter(i.code for i in issues).items())),
            "firewall":firewall or {"active":False},"root_digest":digest(root)}
