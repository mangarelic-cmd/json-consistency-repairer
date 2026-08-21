from __future__ import annotations
import hashlib, json
from typing import Any

CONTRACT="json-consistency-repair.provenance-chain.v1"

def _bytes(v:Any)->bytes:
    return json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(",",":"),default=str,allow_nan=False).encode("utf-8")

def _step(prev:str,event:dict[str,Any])->str:
    h=hashlib.sha256(); h.update(prev.encode("ascii")); h.update(b"\0"); h.update(_bytes(event)); return h.hexdigest()

def build_provenance_chain(*,input_digest:str,output_digest:str,committed:list[Any],cycles:list[dict[str,Any]],code_digest:str,mode:str="single")->dict[str,Any]:
    genesis={"type":"GENESIS","mode":mode,"input_digest":input_digest,"code_digest":code_digest}
    root=hashlib.sha256(_bytes(genesis)).hexdigest(); events=[]; prev=root
    for i,patch in enumerate(committed,1):
        ev={"type":"PATCH","index":i,"patch":patch}; hv=_step(prev,ev); events.append({"event":ev,"previous_hash":prev,"hash":hv}); prev=hv
    for c in cycles:
        ev={"type":"CYCLE","cycle":c.get("cycle"),"digest":c.get("digest",c.get("bundle_digest",c.get("output_digest"))),
            "accepted_count":len(c.get("accepted",[])) if isinstance(c.get("accepted"),list) else c.get("committed_edits",0),
            "strong_quiet":bool(c.get("strong_quiet",False)),"strong_fixed_point_streak":int(c.get("strong_fixed_point_streak",0)),
            "relation_delta":c.get("relation_delta"),"frontier_changed":c.get("frontier_changed"),"oscillation":bool(c.get("oscillation",False)),
            "order_independent":bool((c.get("order_audit") or {}).get("order_independent",True))}
        hv=_step(prev,ev); events.append({"event":ev,"previous_hash":prev,"hash":hv}); prev=hv
    final_event={"type":"FINAL","output_digest":output_digest}
    final_hash=_step(prev,final_event); events.append({"event":final_event,"previous_hash":prev,"hash":final_hash})
    return {"contract":CONTRACT,"algorithm":"SHA-256","genesis":genesis,"genesis_hash":root,"events":events,"root_hash":final_hash}

def verify_provenance_chain(chain:dict[str,Any])->dict[str,Any]:
    try:
        if chain.get("contract")!=CONTRACT: return {"ok":False,"reason":"contract"}
        genesis=chain["genesis"]; root=hashlib.sha256(_bytes(genesis)).hexdigest()
        if root!=chain.get("genesis_hash"): return {"ok":False,"reason":"genesis_hash"}
        prev=root
        for i,row in enumerate(chain.get("events",[])):
            if row.get("previous_hash")!=prev: return {"ok":False,"reason":"previous_hash","index":i}
            hv=_step(prev,row["event"])
            if hv!=row.get("hash"): return {"ok":False,"reason":"event_hash","index":i}
            prev=hv
        if prev!=chain.get("root_hash"): return {"ok":False,"reason":"root_hash"}
        return {"ok":True,"root_hash":prev,"event_count":len(chain.get("events",[]))}
    except Exception as e:
        return {"ok":False,"reason":"exception","detail":type(e).__name__}
