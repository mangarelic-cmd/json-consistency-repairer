from __future__ import annotations

from copy import deepcopy
from collections import Counter, defaultdict
from typing import Any
import hashlib, json

from .models import AnalysisResult, Candidate, Issue, digest, pointer
from .tree import walk, get, decode_pointer
from .analyzers import object_arrays
from .authority_scope import compile_authority_registry, evaluate_authority

SOURCE_REGISTRY_CONTRACT = "json-consistency-repair.source-registry.v1"
IDENTITY_REGISTRY_CONTRACT = "json-consistency-repair.identity-registry.v1"
LIFECYCLE_CONTRACT = "json-consistency-repair.relation-validation-lifecycle.v1"
ASSIMILATION_CONTRACT = "json-consistency-repair.multisource-assimilation.v1"

_ALLOWED_ROLES={"defaults","previous","reference","development","heldout","authoritative","event_log","manifest","schema"}


def _stable(prefix:str, payload:Any, n:int=20)->str:
    raw=json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(",",":"),default=str).encode("utf-8")
    return prefix+"_"+hashlib.sha1(raw).hexdigest()[:n]


def _jkey(v:Any)->str|None:
    try: return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(",",":"))
    except (TypeError,ValueError): return None


def _scalar(v:Any)->bool:
    return isinstance(v,(str,int,float,bool)) and v is not None


def _exists(root:Any,path:str)->bool:
    try: get(root,path); return True
    except (KeyError,IndexError,ValueError,TypeError): return False


def _parent_exists(root:Any,path:str)->bool:
    toks=decode_pointer(path)
    if not toks: return False
    if len(toks)==1: return isinstance(root,(dict,list))
    p=pointer(toks[:-1])
    try: return isinstance(get(root,p),(dict,list))
    except (KeyError,IndexError,ValueError,TypeError): return False


def _candidate(analyzer:str, operation:str, path:str, old:Any, new:Any, reason:str, *, evidence=(), metadata=None, confidence:float=1.0)->Candidate:
    meta=metadata or {}
    cid=_stable("src",[analyzer,operation,path,old,new,meta])[:20]
    return Candidate(cid,analyzer,operation,path,old,new,reason,confidence,1,tuple(evidence),meta)


def source_registry(primary:Any, context:tuple[dict[str,Any],...], manifest:dict[str,Any]|None=None, document:str|None=None)->dict[str,Any]:
    manifest=manifest or {}
    authreg=compile_authority_registry(primary,context,manifest,document=document)
    auth_by={x["source_id"]:x for x in authreg.get("sources") or []}
    rows=[{"source_id":"__primary__","role":"current","digest":digest(primary),"support":"primary","independent_group":"primary","effective_evidence_group":"primary","schema_version":None,"eligible":True,"authority":"CURRENT_STATE"}]
    seen={"__primary__"}; conflicts=[]
    for s in context:
        sid=str(s.get("source_id") or "").strip(); role=str(s.get("role") or "reference")
        if not sid or sid in seen:
            conflicts.append({"source_id":sid,"code":"DUPLICATE_OR_EMPTY_SOURCE_ID"}); continue
        seen.add(sid)
        if role not in _ALLOWED_ROLES:
            conflicts.append({"source_id":sid,"code":"UNKNOWN_SOURCE_ROLE","role":role}); continue
        val=s.get("value"); ar=auth_by.get(sid,{})
        rows.append({"source_id":sid,"role":role,"digest":digest(val),"support":s.get("support","global"),
                     "independent_group":s.get("independent_group",sid),"effective_evidence_group":ar.get("effective_evidence_group",s.get("independent_group",sid)),
                     "schema_version":s.get("schema_version"),"document":s.get("document"),
                     "eligible":bool(s.get("eligible",True)),"authority":ar.get("base_authority") or ("AUTHORITATIVE" if role in {"authoritative","defaults","manifest","schema"} else "CONTEXT"),
                     "authority_scope_count":len(ar.get("authority_scopes") or []),"source_path":s.get("source_path")})
    out={"contract":SOURCE_REGISTRY_CONTRACT,"sources":rows,"source_count":len(rows),"conflicts":conflicts,
         "eligibility_frozen":True,"manifest_digest":digest(manifest or {}),"authority_scope_registry":authreg,
         "evidence_poisoning_firewall":authreg.get("evidence_poisoning_firewall")}
    out["registry_digest"]=digest(out)
    return out


def compile_identity_registry(context:tuple[dict[str,Any],...], manifest:dict[str,Any]|None=None)->dict[str,Any]:
    manifest=manifest or {}; source_ids={str(s.get("source_id")) for s in context}|{"__primary__"}
    maps:dict[str,dict[str,str]]={sid:{} for sid in source_ids}; reverse:dict[str,dict[str,str]]={sid:{} for sid in source_ids}; rows=[]; conflicts=[]
    for idx,b in enumerate(manifest.get("identity_bridges") or []):
        if not isinstance(b,dict): continue
        canonical=str(b.get("canonical_field") or "").strip(); logical=str(b.get("logical_id") or canonical or f"bridge_{idx}")
        if not canonical: conflicts.append({"logical_id":logical,"code":"MISSING_CANONICAL_FIELD"}); continue
        members=[]
        for m in b.get("members") or []:
            if not isinstance(m,dict): continue
            sid=str(m.get("source_id") or ""); field=str(m.get("field") or "")
            if sid not in source_ids or not field: conflicts.append({"logical_id":logical,"code":"INVALID_MEMBER","source_id":sid,"field":field}); continue
            prev=maps[sid].get(field); rev=reverse[sid].get(canonical)
            if (prev is not None and prev!=canonical) or (rev is not None and rev!=field):
                conflicts.append({"logical_id":logical,"code":"AMBIGUOUS_FIELD_IDENTITY","source_id":sid,"field":field,"canonical_field":canonical}); continue
            maps[sid][field]=canonical; reverse[sid][canonical]=field; members.append({"source_id":sid,"field":field})
        rows.append({"logical_id":logical,"canonical_field":canonical,"members":sorted(members,key=lambda x:(x["source_id"],x["field"]))})
    out={"contract":IDENTITY_REGISTRY_CONTRACT,"bridges":sorted(rows,key=lambda x:x["logical_id"]),"conflicts":conflicts,"valid":not conflicts,
         "field_maps":maps,"canonical_to_source_field":reverse}
    out["registry_digest"]=digest({k:v for k,v in out.items() if k!="registry_digest"})
    return out


def _canonicalize_fields(value:Any, field_map:dict[str,str])->tuple[Any,list[dict[str,Any]]]:
    conflicts=[]
    def rec(v,path):
        if isinstance(v,dict):
            out={}
            for k,x in v.items():
                nk=field_map.get(k,k)
                if nk in out and out[nk]!=x:
                    conflicts.append({"path":pointer(path+[nk]),"code":"IDENTITY_COLLISION","source_fields":[k,nk]})
                    continue
                out[nk]=rec(x,path+[nk])
            return out
        if isinstance(v,list): return [rec(x,path+[i]) for i,x in enumerate(v)]
        return deepcopy(v)
    return rec(value,[]),conflicts


def _arrays(root:Any, *, min_len:int=3)->dict[str,list[dict[str,Any]]]:
    # PASS024 uses min_len=1 only for the primary streaming-record wrapper.
    # Discovery sources retain the historical >=3 evidence floor.
    out={}
    def rec(v,parts):
        if isinstance(v,list) and len(v)>=min_len and all(isinstance(x,dict) for x in v):
            out[pointer(parts)]=v
        if isinstance(v,dict):
            for k,x in v.items(): rec(x,parts+[k])
        elif isinstance(v,list):
            for i,x in enumerate(v): rec(x,parts+[i])
    rec(root,[])
    return out


def _derive_functional_models(dev_docs:list[tuple[dict[str,Any],Any]], config)->dict[tuple[str,str,str],dict[str,Any]]:
    max_fields=max(2,int(getattr(config,"source_max_fields",8))); min_support=max(2,int(getattr(config,"source_min_support",4))); min_group=max(1,int(getattr(config,"source_min_group_support",2)))
    raw:dict[tuple[str,str,str],dict[str,Any]]={}
    for meta,doc in dev_docs:
        for ap,arr in _arrays(doc).items():
            fields=sorted(set().union(*(o.keys() for o in arr)))[:max_fields]
            for det in fields:
                for target in fields:
                    if det==target: continue
                    groups=defaultdict(Counter); observed=0
                    for o in arr:
                        if _scalar(o.get(det)) and target in o and o[target] is not None:
                            dk,tv=_jkey(o[det]),_jkey(o[target])
                            if dk is not None and tv is not None: groups[dk][tv]+=1; observed+=1
                    if observed<min_support: continue
                    mapping={}; support=0; conflict=False
                    for dk,cnt in groups.items():
                        total=sum(cnt.values())
                        if total<min_group: continue
                        if len(cnt)!=1: conflict=True; break
                        tv,n=cnt.most_common(1)[0]; mapping[dk]=json.loads(tv); support+=n
                    if conflict or support<min_support or not mapping: continue
                    key=(ap,det,target); row=raw.setdefault(key,{"array_path":ap,"determinant":det,"target":target,"mapping":{},"development_sources":set(),"support":0,"development_conflict":False})
                    for dk,v in mapping.items():
                        if dk in row["mapping"] and row["mapping"][dk]!=v: row["development_conflict"]=True
                        else: row["mapping"][dk]=v
                    row["development_sources"].add(meta["source_id"]); row["support"]+=support
    return raw


def _compatible_support(dev_meta:dict[str,Any], held_meta:dict[str,Any])->bool:
    a=dev_meta.get("support","global"); b=held_meta.get("support","global")
    return a in (None,"global","*") or b in (None,"global","*") or a==b


def _lifecycle_models(primary:Any, context_meta:list[dict[str,Any]], canonical_docs:dict[str,Any], identity:dict[str,Any], config)->tuple[AnalysisResult,dict[str,Any]]:
    out=AnalysisResult(); meta_by_id={m["source_id"]:m for m in context_meta}; dev=[(m,canonical_docs[m["source_id"]]) for m in context_meta if m["role"]=="development" and m.get("eligible") and m["source_id"] in canonical_docs]
    held=[(m,canonical_docs[m["source_id"]]) for m in context_meta if m["role"]=="heldout" and m.get("eligible") and m["source_id"] in canonical_docs]
    models=_derive_functional_models(dev,config); rows=[]
    primary_map=(identity.get("field_maps") or {}).get("__primary__",{}); primary_rev=(identity.get("canonical_to_source_field") or {}).get("__primary__",{})
    primary_can,_=_canonicalize_fields(primary,primary_map); parrays=_arrays(primary_can,min_len=1)
    for key,model in sorted(models.items()):
        ap,det,target=key; violations=[]; confirms=0; testable=0; groups=set(); dependent_groups=set()
        dev_groups={meta_by_id[s].get("effective_evidence_group",meta_by_id[s].get("independent_group",s)) for s in model["development_sources"] if s in meta_by_id}
        for hm,hdoc in held:
            if not any(_compatible_support(meta_by_id[s],hm) for s in model["development_sources"] if s in meta_by_id): continue
            arr=_arrays(hdoc).get(ap,[]); local_test=0; local_bad=[]
            for i,o in enumerate(arr):
                dk=_jkey(o.get(det)) if _scalar(o.get(det)) else None
                if dk is None or dk not in model["mapping"] or target not in o: continue
                local_test+=1; testable+=1
                if o[target]!=model["mapping"][dk]: local_bad.append({"source_id":hm["source_id"],"record":i,"determinant":o.get(det),"observed":o.get(target),"expected":model["mapping"][dk]})
            if local_test:
                grp=hm.get("effective_evidence_group",hm.get("independent_group",hm["source_id"]))
                if grp in dev_groups: dependent_groups.add(grp)
                elif local_bad: violations.extend(local_bad)
                else: groups.add(grp); confirms+=local_test
        if model["development_conflict"]: state="DEVELOPMENT_CONFLICT"
        elif violations: state="GLOBAL_REFUTED"
        elif len(groups)>=2: state="PORTABLE"
        elif len(groups)==1: state="HELDOUT_CONFIRMED"
        elif dependent_groups: state="DEPENDENT_REPLICATION_ONLY"
        else: state="DISCOVERED"
        rel={"kind":"cross_source_functional","array_path":ap,"inputs":[det],"output":target,"determinant":det,"target":target,
             "support":model["support"],"confidence":1.0,"direction_certified":state in {"HELDOUT_CONFIRMED","PORTABLE"},"direction_source":"independent_heldout" if state in {"HELDOUT_CONFIRMED","PORTABLE"} else "development_only",
             "constraint_source":"derived_exact" if state in {"HELDOUT_CONFIRMED","PORTABLE"} else "development",
             "validation_state":state,"development_sources":sorted(model["development_sources"]),"heldout_independent_groups":sorted(groups),
             "counterexample_count":len(violations),"testable_heldout_rows":testable}
        rel["relation_id"]=_stable("msrel",{k:v for k,v in rel.items() if k not in {"support","confidence"}})[6:]
        out.relations.append(rel)
        row={"relation_id":rel["relation_id"],"array_path":ap,"determinant":det,"target":target,"state":state,"development_sources":sorted(model["development_sources"]),"heldout_independent_groups":sorted(groups),"dependent_groups":sorted(dependent_groups),"counterexamples":violations[:32],"counterexample_count":len(violations),"testable_heldout_rows":testable}
        rows.append(row)
        if state=="GLOBAL_REFUTED":
            out.issues.append(Issue("multisource_lifecycle","global_relation_refuted","",f"A development relation {det!r}->{target!r} has an independent heldout counterexample.","warning",False,{"relation_id":rel["relation_id"],"counterexample_count":len(violations),"validation_state":state}))
            continue
        if state not in {"HELDOUT_CONFIRMED","PORTABLE"}: continue
        arr=parrays.get(ap,[]); actual_target=primary_rev.get(target,target); actual_det=primary_rev.get(det,det)
        for i,o in enumerate(arr):
            dk=_jkey(o.get(det)) if _scalar(o.get(det)) else None
            if dk is None or dk not in model["mapping"]: continue
            expected=model["mapping"][dk]
            if target in o and o[target]==expected: continue
            path=pointer(decode_pointer(ap)+[i,actual_target]); exists=_exists(primary,path); old=get(primary,path) if exists else None
            if not exists and not _parent_exists(primary,path): continue
            meta={"relation_id":rel["relation_id"],"relation_kind":"cross_source_functional","constraint_source":"derived_exact","validation_state":state,"determinant":actual_det,"target":actual_target,"heldout_independent_groups":sorted(groups),"development_sources":sorted(model["development_sources"]),"add_if_missing":not exists}
            ev=tuple([f"DEV:{s}" for s in sorted(model["development_sources"])]+[f"HELDOUT:{g}" for g in sorted(groups)])
            op="replace" if exists else "add"
            out.issues.append(Issue("multisource_lifecycle","heldout_validated_relation_violation",path,"Value violates a relation independently confirmed on heldout sources.","warning",True,meta))
            out.candidates.append(_candidate("multisource_lifecycle",op,path,old,expected,"Restore independently heldout-validated cross-source relation.",evidence=ev,metadata=meta))
    cert={"contract":LIFECYCLE_CONTRACT,"relations":rows,"relation_count":len(rows),"heldout_confirmed":sum(r["state"]=="HELDOUT_CONFIRMED" for r in rows),"portable":sum(r["state"]=="PORTABLE" for r in rows),"global_refuted":sum(r["state"]=="GLOBAL_REFUTED" for r in rows),"dependent_only":sum(r["state"]=="DEPENDENT_REPLICATION_ONLY" for r in rows)}
    cert["lifecycle_digest"]=digest(cert)
    return out,cert


def _leaf_paths(root:Any)->list[tuple[str,Any]]:
    return [(p,v) for p,v in walk(root) if p and not isinstance(v,(dict,list))]


def _assimilation_candidates(primary:Any, context_meta:list[dict[str,Any]], context_docs:dict[str,Any], manifest:dict[str,Any], authority_registry:dict[str,Any])->tuple[AnalysisResult,dict[str,Any]]:
    out=AnalysisResult(); actions=[]; historical=[]; gated=[]; authority_proofs=[]
    eval_ctx=authority_registry.get("evaluation") or {}
    def auth(sid,path,operation):
        pr=evaluate_authority(authority_registry,sid,target_path=path,operation=operation,document=eval_ctx.get("document"),schema_version=eval_ctx.get("schema_version"),evaluation_time=eval_ctx.get("evaluation_time"))
        authority_proofs.append(pr); return pr
    # Defaults are authoritative fallback only inside their declared scope, and never override an observed value.
    for m in context_meta:
        sid=m["source_id"]; role=m["role"]; doc=context_docs.get(sid)
        if doc is None or not m.get("eligible"): continue
        if role=="defaults":
            for p,v in _leaf_paths(doc):
                if _exists(primary,p) or not _parent_exists(primary,p): continue
                pr=auth(sid,p,"add")
                if not pr.get("authorized"):
                    gated.append({"source_id":sid,"kind":"DEFAULT_SCOPE_GATE","path":p,"reason":pr.get("reason"),"authority_proof_sha256":pr.get("proof_sha256")}); continue
                meta={"constraint_source":"authoritative","source_role":"defaults","source_id":sid,"relation_kind":"multisource_default","add_if_missing":True,
                      "authority_proof_sha256":pr["proof_sha256"],"authority_proof":deepcopy(pr),"authority_scope_contract":pr["contract"],"delegation_chain":pr.get("delegation_chain",[]),
                      "effective_evidence_group":pr.get("effective_evidence_group")}
                c=_candidate("multisource_defaults","add",p,None,v,"Fill missing value from explicit scoped defaults source.",evidence=(f"SOURCE:{sid}",),metadata=meta)
                out.issues.append(Issue("multisource_defaults","missing_value_with_default",p,"Missing current value has an explicit in-scope default.","warning",True,meta)); out.candidates.append(c)
                actions.append({"source_id":sid,"kind":"DEFAULT_FALLBACK","path":p,"candidate_id":c.candidate_id,"authority_proof_sha256":pr["proof_sha256"]})
        elif role=="previous":
            for p,v in _leaf_paths(doc):
                if not _exists(primary,p): historical.append({"source_id":sid,"path":p,"status":"AVAILABLE_BUT_NOT_CARRIED_FORWARD"})
                else:
                    try:
                        if get(primary,p)!=v: historical.append({"source_id":sid,"path":p,"status":"CURRENT_DIFFERS_FROM_PREVIOUS"})
                    except Exception: pass
    # Explicit authoritative values must be in source scope before becoming candidates.
    for r in manifest.get("authoritative_values") or []:
        if not isinstance(r,dict): continue
        sid=str(r.get("source_id") or ""); sp=str(r.get("source_path") or r.get("path") or ""); tp=str(r.get("target_path") or sp)
        m=next((x for x in context_meta if x["source_id"]==sid),None); doc=context_docs.get(sid)
        if not m or not sp or not _exists(doc,sp): continue
        val=get(doc,sp); exists=_exists(primary,tp); old=get(primary,tp) if exists else None
        if exists and old==val: continue
        if not exists and not _parent_exists(primary,tp): continue
        op="replace" if exists else "add"; pr=auth(sid,tp,op)
        if not pr.get("authorized"):
            gated.append({"source_id":sid,"kind":"AUTHORITATIVE_VALUE_SCOPE_GATE","path":tp,"reason":pr.get("reason"),"authority_proof_sha256":pr.get("proof_sha256")})
            out.issues.append(Issue("multisource_authority","authority_scope_denied",tp,"Explicit cross-source authority does not cover this target path/operation/context.","warning",False,{"source_id":sid,"reason":pr.get("reason"),"authority_proof_sha256":pr.get("proof_sha256")}))
            continue
        meta={"constraint_source":"authoritative","source_role":m["role"],"source_id":sid,"relation_kind":"multisource_authoritative_value","source_path":sp,"target_path":tp,"add_if_missing":not exists,
              "authority_proof_sha256":pr["proof_sha256"],"authority_proof":deepcopy(pr),"authority_scope_contract":pr["contract"],"delegation_chain":pr.get("delegation_chain",[]),
              "effective_evidence_group":pr.get("effective_evidence_group")}
        c=_candidate("multisource_authority",op,tp,old,val,"Restore explicit scoped authoritative cross-source value.",evidence=(f"SOURCE:{sid}",),metadata=meta)
        out.issues.append(Issue("multisource_authority","authoritative_source_mismatch",tp,"Current value conflicts with an explicitly scoped authoritative source value.","error",True,meta)); out.candidates.append(c)
        actions.append({"source_id":sid,"kind":"AUTHORITATIVE_VALUE","path":tp,"candidate_id":c.candidate_id,"authority_proof_sha256":pr["proof_sha256"]})
    # Event-log projection remains explicit and additionally requires scoped mutation authority.
    for r in manifest.get("projections") or []:
        if not isinstance(r,dict) or r.get("kind")!="last_event_value": continue
        sid=str(r.get("source_id") or ""); m=next((x for x in context_meta if x["source_id"]==sid),None); doc=context_docs.get(sid)
        if not m or m["role"]!="event_log": continue
        ep=str(r.get("events_path") or ""); events=doc if ep=="" else (get(doc,ep) if _exists(doc,ep) else None)
        if not isinstance(events,list): continue
        pf=str(r.get("path_field") or "path"); vf=str(r.get("value_field") or "value"); target=str(r.get("target_path") or "")
        vals=[e[vf] for e in events if isinstance(e,dict) and e.get(pf)==target and vf in e]
        if not vals or not target: continue
        val=vals[-1]; exists=_exists(primary,target); old=get(primary,target) if exists else None
        if exists and old==val: continue
        if not exists and not _parent_exists(primary,target): continue
        authoritative=bool(r.get("authoritative",False)); op="replace" if exists else "add"; pr=auth(sid,target,op) if authoritative else None
        if authoritative and not pr.get("authorized"):
            gated.append({"source_id":sid,"kind":"EVENT_PROJECTION_SCOPE_GATE","path":target,"reason":pr.get("reason"),"authority_proof_sha256":pr.get("proof_sha256")}); continue
        meta={"constraint_source":"authoritative" if authoritative else "derived_exact","source_role":"event_log","source_id":sid,"relation_kind":"event_log_projection","event_count":len(vals),"add_if_missing":not exists}
        if pr:
            meta.update({"authority_proof_sha256":pr["proof_sha256"],"authority_proof":deepcopy(pr),"authority_scope_contract":pr["contract"],"delegation_chain":pr.get("delegation_chain",[]),"effective_evidence_group":pr.get("effective_evidence_group")})
        c=_candidate("multisource_event_projection",op,target,old,val,"Project explicit last event value onto current state.",evidence=(f"EVENT_LOG:{sid}",),metadata=meta)
        out.issues.append(Issue("multisource_event_projection","event_projection_mismatch",target,"Current state differs from an explicit event-log projection.","warning",authoritative,meta))
        if authoritative: out.candidates.append(c); actions.append({"source_id":sid,"kind":"EVENT_LAST_VALUE","path":target,"candidate_id":c.candidate_id,"authority_proof_sha256":pr["proof_sha256"]})
    # Stable unique proof list.
    authority_proofs=list({p.get("proof_sha256"):p for p in authority_proofs if p.get("proof_sha256")}.values())
    cert={"contract":ASSIMILATION_CONTRACT,"actions":actions,"gated_actions":gated,"historical_observations":historical[:256],"historical_observation_count":len(historical),
          "candidate_count":len(out.candidates),"authority_proofs":sorted(authority_proofs,key=lambda x:x.get("proof_sha256","")),"authority_proof_count":len(authority_proofs)}
    return out,cert


def analyze_multisource(primary:Any, config)->tuple[AnalysisResult,dict[str,Any]]:
    context=tuple(getattr(config,"source_context",()) or ()); manifest=deepcopy(getattr(config,"source_manifest",None) or {})
    if not bool(getattr(config,"enable_multisource",True)) or not context:
        sr=source_registry(primary,(),manifest)
        empty={"contract":ASSIMILATION_CONTRACT,"enabled":False,"source_registry":sr,"identity_registry":compile_identity_registry((),manifest),
               "authority_scope_registry":sr.get("authority_scope_registry"),"evidence_poisoning_firewall":sr.get("evidence_poisoning_firewall"),
               "relation_lifecycle":{"contract":LIFECYCLE_CONTRACT,"relations":[],"relation_count":0},"assimilation":{"contract":ASSIMILATION_CONTRACT,"actions":[],"candidate_count":0,"authority_proofs":[]}}
        empty["assimilation_digest"]=digest(empty); return AnalysisResult(),empty
    document=getattr(config,"logic_document",None) or getattr(config,"system_document",None) or getattr(config,"conservation_document",None) or getattr(config,"moment_document",None)
    reg=source_registry(primary,context,manifest,document=document); identity=compile_identity_registry(context,manifest)
    meta=[x for x in reg["sources"] if x["source_id"]!="__primary__"]; fmap=identity.get("field_maps") or {}; docs={}; identity_collisions=[]
    byid={str(s.get("source_id")):s for s in context}
    for m in meta:
        sid=m["source_id"]; val=byid[sid].get("value"); can,coll=_canonicalize_fields(val,fmap.get(sid,{})); docs[sid]=can
        for c in coll: identity_collisions.append({"source_id":sid,**c})
    authreg=reg.get("authority_scope_registry") or compile_authority_registry(primary,context,manifest,document=document)
    ass,asscert=_assimilation_candidates(primary,meta,{m["source_id"]:byid[m["source_id"]].get("value") for m in meta},manifest,authreg)
    life,lifecert=_lifecycle_models(primary,meta,docs,identity,config)
    out=AnalysisResult(ass.issues+life.issues,ass.candidates+life.candidates,ass.relations+life.relations)
    if reg["conflicts"] or identity.get("conflicts") or identity_collisions:
        out.issues.append(Issue("multisource_registry","source_registry_conflict","","Multi-source registry or identity bridges are inconsistent.","error",False,{"source_conflicts":reg["conflicts"],"identity_conflicts":identity.get("conflicts",[]),"identity_collisions":identity_collisions[:32]}))
    cert={"contract":ASSIMILATION_CONTRACT,"enabled":True,"source_registry":reg,"identity_registry":identity,"identity_collisions":identity_collisions,"assimilation":asscert,"relation_lifecycle":lifecert,
          "authority_scope_registry":authreg,"evidence_poisoning_firewall":authreg.get("evidence_poisoning_firewall"),
          "policy":{"previous":"OBSERVER_ONLY","defaults":"FILL_MISSING_ONLY_WITHIN_SCOPE","heldout":"COUNTEREXAMPLE_OVERRIDES_PROMOTION","same_effective_evidence_group":"NOT_HELDOUT","unknown_existing":"NOT_INVENTED","authority":"PATH_DOCUMENT_SCHEMA_TIME_OPERATION_SCOPED"}}
    cert["assimilation_digest"]=digest(cert)
    return out,cert


def multisource_summary(analysis:AnalysisResult, cert:dict[str,Any])->dict[str,Any]:
    life=cert.get("relation_lifecycle") or {}; assim=cert.get("assimilation") or {}; reg=cert.get("source_registry") or {}
    return {"contract":"json-consistency-repair.multisource-summary.v1","enabled":bool(cert.get("enabled")),"source_count":reg.get("source_count",0),"candidate_count":len([c for c in analysis.candidates if c.analyzer.startswith("multisource")]),
            "heldout_confirmed":life.get("heldout_confirmed",0),"portable":life.get("portable",0),"global_refuted":life.get("global_refuted",0),"historical_observation_count":assim.get("historical_observation_count",0),"assimilation_digest":cert.get("assimilation_digest")}
