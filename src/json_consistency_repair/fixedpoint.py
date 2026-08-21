from __future__ import annotations
from copy import deepcopy
from typing import Any, Callable
import hashlib, json
from .models import Candidate, digest


def relation_strength(rel:dict[str,Any])->tuple[str,str]:
    return (str(rel.get("confidence","")),str(rel.get("support","")))


def relation_snapshot(relations:list[dict[str,Any]])->dict[str,tuple[str,str]]:
    return {str(r["relation_id"]):relation_strength(r) for r in relations}


def frontier_signature(candidates:list[Candidate])->str:
    rows=sorted((c.path,json.dumps(c.new_value,sort_keys=True,ensure_ascii=False,default=str,separators=(",",":")),c.analyzer) for c in candidates)
    return hashlib.sha256(json.dumps(rows,ensure_ascii=False,separators=(",",":")).encode()).hexdigest()


def relation_delta(previous:dict[str,tuple[str,str]]|None,current:dict[str,tuple[str,str]])->dict[str,Any]:
    if previous is None:
        return {"new":sorted(current),"retired":[],"strength_changed":[],"quiet":False}
    new=sorted(set(current)-set(previous)); retired=sorted(set(previous)-set(current)); changed=[]
    for rid in sorted(set(previous)&set(current)):
        if previous[rid]!=current[rid]: changed.append({"relation_id":rid,"before":list(previous[rid]),"after":list(current[rid])})
    return {"new":new,"retired":retired,"strength_changed":changed,"quiet":not(new or retired or changed)}


def update_lifecycle(ledger:dict[str,Any], relations:list[dict[str,Any]], cycle:int)->list[dict[str,Any]]:
    current={str(r["relation_id"]):r for r in relations}; events=[]
    for rid,entry in list(ledger.items()):
        if rid not in current and entry.get("state")!="RETIRED":
            entry["state"]="RETIRED"; entry["retired_cycle"]=cycle; events.append({"relation_id":rid,"state":"RETIRED"})
    for rid,rel in current.items():
        strength=list(relation_strength(rel)); entry=ledger.get(rid)
        if entry is None:
            ledger[rid]={"state":"DISCOVERED","first_seen_cycle":cycle,"last_seen_cycle":cycle,"seen_cycles":1,"relation":rel,
                         "strength":strength,"stable_cycles":0,"promotion_gate":"COLD_REPLAY_REQUIRED"}
            events.append({"relation_id":rid,"state":"DISCOVERED"}); continue
        prev=entry.get("strength"); entry["last_seen_cycle"]=cycle; entry["seen_cycles"]=int(entry.get("seen_cycles",0))+1; entry["relation"]=rel
        if prev==strength:
            entry["stable_cycles"]=int(entry.get("stable_cycles",0))+1
            if entry["stable_cycles"]>=1: state="STABLE"
            else: state=entry.get("state","UPDATED")
        else:
            try:
                po=float(prev[0]); pn=float(strength[0]); so=float(prev[1]); sn=float(strength[1]);
                state="REINFORCED" if (pn>=po and sn>=so and (pn>po or sn>so)) else ("WEAKENED" if (pn<=po and sn<=so and (pn<po or sn<so)) else "UPDATED")
            except Exception: state="UPDATED"
            entry["stable_cycles"]=0
        entry["state"]=state; entry["strength"]=strength; entry["promotion_gate"]="COLD_REPLAY_REQUIRED"
        events.append({"relation_id":rid,"state":state})
    return events


def audit_patch_order(root:Any, patches:list[Candidate], apply_fn:Callable[[Any,Candidate],bool])->dict[str,Any]:
    if len(patches)<=1:
        return {"selected_patch_count":len(patches),"order_independent":True,"tested_orders":1,"forward_digest":None,"reverse_digest":None}
    a=deepcopy(root); oka=True
    for c in patches:
        if not apply_fn(a,c): oka=False; break
    b=deepcopy(root); okb=True
    for c in reversed(patches):
        if not apply_fn(b,c): okb=False; break
    da=digest(a) if oka else None; db=digest(b) if okb else None
    return {"selected_patch_count":len(patches),"order_independent":bool(oka and okb and da==db),"tested_orders":2,
            "forward_digest":da,"reverse_digest":db,"forward_ok":oka,"reverse_ok":okb}
