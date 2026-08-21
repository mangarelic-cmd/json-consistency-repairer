from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterable
import fnmatch

from .models import AnalysisResult, Candidate, Issue, digest
from .tree import decode_pointer
from .jsonpatch_exact import apply_candidate

CONTRACT = "json-consistency-repair.repair-controllability.v1"
FIREWALL_CONTRACT = "json-consistency-repair.controllability-firewall.v1"


def _canon_path(path: str) -> str:
    if path in {"", "/"}:
        return ""
    return path if path.startswith("/") else "/" + path


def _segments(path: str) -> list[str]:
    try:
        return [str(x) for x in decode_pointer(_canon_path(path))]
    except Exception:
        return []


def _path_match(pattern: str, path: str) -> bool:
    """JSON-pointer-aware glob: * matches one segment, ** matches the remaining suffix."""
    p = _segments(pattern)
    t = _segments(path)
    def rec(i: int, j: int) -> bool:
        while i < len(p):
            tok = p[i]
            if tok == "**":
                if i == len(p) - 1:
                    return True
                return any(rec(i + 1, k) for k in range(j, len(t) + 1))
            if j >= len(t) or (tok != "*" and tok != t[j]):
                return False
            i += 1; j += 1
        return j == len(t)
    return rec(0, 0)


def _rule_id(rule: dict[str, Any], index: int) -> str:
    return str(rule.get("rule_id") or rule.get("control_rule_id") or f"control_{index:04d}")


def _public_rules(config: Any) -> list[dict[str, Any]]:
    out=[]
    for i, raw in enumerate(getattr(config, "controllability_rules", ()) or ()):
        if not isinstance(raw, dict):
            continue
        r=deepcopy(raw); r.setdefault("rule_id", _rule_id(r, i)); out.append(r)
    return out


def _action_rows(candidate: Candidate, document: str | None = None) -> list[dict[str, Any]]:
    """A plan candidate is atomic at publication but every internal write still needs permission."""
    meta=candidate.metadata or {}
    if candidate.operation == "plan" and isinstance(meta.get("steps"), list):
        rows=[]
        for i, step in enumerate(meta.get("steps") or []):
            if not isinstance(step, dict):
                continue
            rows.append({
                "candidate_id":candidate.candidate_id,
                "substep":i,
                "operation":str(step.get("operation") or "replace"),
                "path":str(step.get("path") or ""),
                "document":document,
            })
        if rows:
            return rows
    op=candidate.operation
    if op=="replace" and bool((candidate.metadata or {}).get("add_if_missing")) and candidate.old_value is None:
        op="add"
    return [{"candidate_id":candidate.candidate_id,"substep":None,"operation":op,"path":candidate.path,"document":document}]


def _rule_applies(rule: dict[str, Any], action: dict[str, Any]) -> bool:
    doc = rule.get("document")
    if doc not in (None, "", "*") and str(doc) != str(action.get("document") or ""):
        return False
    pattern = str(rule.get("path_pattern") if rule.get("path_pattern") is not None else rule.get("path") or "**")
    return _path_match(pattern, str(action.get("path") or ""))


def _individual_permission(action: dict[str, Any], rules: list[dict[str, Any]], *, require_explicit: bool) -> dict[str, Any]:
    matching=[r for r in rules if str(r.get("kind") or "mutation_policy") != "budget" and _rule_applies(r, action)]
    reasons=[]; allowed=True
    if require_explicit and not matching:
        allowed=False; reasons.append("EXPLICIT_MUTATION_PERMISSION_REQUIRED")
    for r in matching:
        rid=str(r.get("rule_id"))
        if bool(r.get("immutable")):
            allowed=False; reasons.append(f"IMMUTABLE:{rid}")
        denied={str(x) for x in (r.get("denied_operations") or [])}
        if action["operation"] in denied or "*" in denied:
            allowed=False; reasons.append(f"OPERATION_DENIED:{rid}")
        if "allowed_operations" in r:
            permitted={str(x) for x in (r.get("allowed_operations") or [])}
            if action["operation"] not in permitted and "*" not in permitted:
                allowed=False; reasons.append(f"OPERATION_NOT_ALLOWED:{rid}")
    return {
        **action,
        "allowed":allowed,
        "matching_rule_ids":[str(r.get("rule_id")) for r in matching],
        "explicitly_covered":bool(matching),
        "reasons":reasons,
    }


def _candidate_permission(candidate: Candidate, rules: list[dict[str, Any]], *, require_explicit: bool, document: str | None = None) -> dict[str, Any]:
    actions=[_individual_permission(a,rules,require_explicit=require_explicit) for a in _action_rows(candidate,document)]
    return {
        "candidate_id":candidate.candidate_id,
        "document":document,
        "cost":int(candidate.cost),
        "actions":actions,
        "allowed":all(a["allowed"] for a in actions),
        "explicitly_covered":all(a["explicitly_covered"] for a in actions),
    }


def _active(config: Any) -> bool:
    return bool(getattr(config,"enable_controllability",True) and (
        getattr(config,"controllability_rules",()) or
        getattr(config,"require_explicit_mutation_permission",False) or
        getattr(config,"max_control_edits",None) is not None or
        getattr(config,"max_control_cost",None) is not None
    ))


def apply_controllability_firewall(root: Any, analysis: AnalysisResult, config: Any, *, document: str | None = None) -> tuple[AnalysisResult, dict[str, Any]]:
    """Remove mutation candidates that cannot legally be actuated.

    This occurs before optimization so a slightly more expensive legal repair can defeat an
    individually cheaper but forbidden repair.  No policy => exact legacy behavior.
    """
    rules=_public_rules(config)
    if not _active(config):
        cert={"contract":FIREWALL_CONTRACT,"enabled":False,"status":"UNCONSTRAINED_LEGACY","rules":[],
              "candidate_count":len(analysis.candidates),"allowed_candidate_count":len(analysis.candidates),"blocked_candidate_count":0,"checks":[]}
        cert["certificate_sha256"]=digest(cert)
        return analysis,cert
    checks=[]; allowed=[]; blocked=[]
    require_explicit=bool(getattr(config,"require_explicit_mutation_permission",False))
    for c in analysis.candidates:
        row=_candidate_permission(c,rules,require_explicit=require_explicit,document=document)
        checks.append(row)
        if row["allowed"]:
            allowed.append(c)
        else:
            blocked.append((c,row))
    issues=list(analysis.issues)
    # Preserve original evidence and add one explicit terminal per blocked target.  This is not
    # repairable by the current action set; a future permission/budget change may wake it.
    seen=set()
    for c,row in blocked:
        key=(document,c.path)
        if key in seen: continue
        seen.add(key)
        reasons=sorted({r for a in row["actions"] for r in a["reasons"]})
        issues.append(Issue("controllability","IDENTIFIABLE_BUT_UNREACHABLE",c.path,
                            "A candidate repair is identifiable but forbidden by the active mutation-control contract.",
                            "error",False,{"candidate_id":c.candidate_id,"document":document,"reasons":reasons}))
    out=AnalysisResult(issues,allowed,list(analysis.relations))
    cert={"contract":FIREWALL_CONTRACT,"enabled":True,
          "status":"IDENTIFIABLE_BUT_UNREACHABLE" if blocked else "CANDIDATE_FRONTIER_REACHABLE",
          "rules":rules,"require_explicit_mutation_permission":require_explicit,
          "candidate_count":len(analysis.candidates),"allowed_candidate_count":len(allowed),"blocked_candidate_count":len(blocked),
          "checks":checks}
    cert["certificate_sha256"]=digest(cert)
    return out,cert


def _budget(config: Any, rules: list[dict[str, Any]], document: str | None) -> dict[str, Any]:
    edit_caps=[]; cost_caps=[]
    if getattr(config,"max_control_edits",None) is not None:
        edit_caps.append(int(getattr(config,"max_control_edits")))
    if getattr(config,"max_control_cost",None) is not None:
        cost_caps.append(int(getattr(config,"max_control_cost")))
    for r in rules:
        if str(r.get("kind") or "") != "budget":
            continue
        rdoc=r.get("document")
        if rdoc not in (None,"","*") and str(rdoc)!=str(document or ""):
            continue
        if r.get("max_edits") is not None: edit_caps.append(int(r["max_edits"]))
        if r.get("max_cost") is not None: cost_caps.append(int(r["max_cost"]))
    return {"max_edits":min(edit_caps) if edit_caps else None,"max_cost":min(cost_caps) if cost_caps else None}


def _precedence_edges(candidates: list[Candidate], rules: list[dict[str, Any]], document: str | None) -> list[tuple[str,str,str]]:
    edges=[]
    for r in rules:
        precedes=r.get("must_precede") or r.get("precedes")
        if not precedes:
            continue
        if isinstance(precedes,str): precedes=[precedes]
        srcpat=str(r.get("path_pattern") if r.get("path_pattern") is not None else r.get("path") or "**")
        rid=str(r.get("rule_id"))
        for a in candidates:
            if not any(_path_match(srcpat,x["path"]) for x in _action_rows(a,document)): continue
            for b in candidates:
                if a.candidate_id==b.candidate_id: continue
                if any(any(_path_match(str(dst),x["path"]) for x in _action_rows(b,document)) for dst in precedes):
                    edges.append((a.candidate_id,b.candidate_id,rid))
    return sorted(set(edges))


def _toposort(ids: list[str], edges: list[tuple[str,str,str]]) -> tuple[list[str] | None, list[list[str]]]:
    succ={x:set() for x in ids}; indeg={x:0 for x in ids}
    for a,b,_ in edges:
        if a not in succ or b not in succ or b in succ[a]: continue
        succ[a].add(b); indeg[b]+=1
    ready=sorted(x for x in ids if indeg[x]==0); order=[]
    while ready:
        x=ready.pop(0); order.append(x)
        for y in sorted(succ[x]):
            indeg[y]-=1
            if indeg[y]==0:
                ready.append(y); ready.sort()
    if len(order)==len(ids): return order,[]
    cyc=sorted(x for x in ids if indeg[x]>0)
    return None,[cyc] if cyc else []


def compile_control_plan(root: Any, candidates: Iterable[Candidate], config: Any, *, document: str | None = None,
                         preserve_order: bool = False, used_edits: int = 0, used_cost: int = 0) -> tuple[list[Candidate], dict[str, Any]]:
    """Compile and replay the actual legal action sequence for a selected repair set."""
    cands=list(candidates); rules=_public_rules(config)
    if not cands:
        cert={"contract":CONTRACT,"enabled":_active(config),"status":"NO_ACTION_REQUIRED","reachability":"NO_ACTION",
              "controllability":"NO_ACTION","document":document,"rules":rules,"requested_action_count":0,
              "budget_used_before":{"edits":max(0,int(used_edits)),"cost":max(0,int(used_cost))},
              "selected_order":[],"checks":{"permissions_ok":True,"budget_ok":True,"precedence_ok":True,"replay_ok":True}}
        cert["certificate_sha256"]=digest(cert); return [],cert
    permissions=[_candidate_permission(c,rules,require_explicit=bool(getattr(config,"require_explicit_mutation_permission",False)),document=document) for c in cands]
    permissions_ok=all(x["allowed"] for x in permissions)
    budget=_budget(config,rules,document); total_cost=sum(max(0,int(c.cost)) for c in cands)
    used_edits=max(0,int(used_edits)); used_cost=max(0,int(used_cost))
    projected_edits=used_edits+len(cands); projected_cost=used_cost+total_cost
    budget_ok=(budget["max_edits"] is None or projected_edits<=budget["max_edits"]) and (budget["max_cost"] is None or projected_cost<=budget["max_cost"])
    edges=_precedence_edges(cands,rules,document)
    ids=[c.candidate_id for c in cands]
    if preserve_order:
        pos={x:i for i,x in enumerate(ids)}
        precedence_ok=all(pos.get(a,-1)<pos.get(b,-1) for a,b,_ in edges)
        order=ids if precedence_ok else None; cycles=[]
    else:
        order,cycles=_toposort(ids,edges); precedence_ok=order is not None
    byid={c.candidate_id:c for c in cands}
    ordered=[byid[x] for x in order] if order and len(byid)==len(cands) else []
    trial=deepcopy(root); replay_ok=bool(ordered)
    if replay_ok:
        for c in ordered:
            if not apply_candidate(trial,c): replay_ok=False; break
    explicit=all(x["explicitly_covered"] for x in permissions)
    ok=bool(permissions_ok and budget_ok and precedence_ok and replay_ok)
    if ok and explicit:
        status="CONTROLLABLE"
    elif ok:
        status="REACHABLE_UNDER_OPEN_CONTROL_WORLD"
    else:
        status="IDENTIFIABLE_BUT_UNREACHABLE"
    cert={"contract":CONTRACT,"enabled":_active(config),"status":status,
          "reachability":"REACHABLE" if ok else "UNREACHABLE",
          "controllability":"EXPLICITLY_CONTROLLABLE" if ok and explicit else ("OPEN_WORLD_REACHABLE" if ok else "NOT_CONTROLLABLE"),
          "document":document,"rules":rules,"requested_action_count":len(cands),"requested_cost":total_cost,"budget":budget,
          "budget_used_before":{"edits":used_edits,"cost":used_cost},"budget_projected":{"edits":projected_edits,"cost":projected_cost},
          "permissions":permissions,"precedence_edges":[{"before":a,"after":b,"rule_id":r} for a,b,r in edges],
          "preserve_input_order":preserve_order,"selected_order":order or [],"precedence_cycles":cycles,
          "target_digest":digest(trial) if replay_ok else None,
          "checks":{"permissions_ok":permissions_ok,"budget_ok":budget_ok,"precedence_ok":precedence_ok,"replay_ok":replay_ok,
                    "explicit_control_coverage":explicit}}
    cert["certificate_sha256"]=digest(cert)
    return (ordered if ok else []),cert


def verify_controllability_certificate(cert: dict[str, Any]) -> bool:
    if not isinstance(cert,dict) or cert.get("contract") not in {CONTRACT,FIREWALL_CONTRACT}:
        return False
    supplied=cert.get("certificate_sha256")
    if not supplied: return False
    tmp=deepcopy(cert); tmp.pop("certificate_sha256",None)
    if digest(tmp)!=supplied: return False
    if cert.get("contract")==FIREWALL_CONTRACT:
        if cert.get("enabled") is False:
            return cert.get("blocked_candidate_count")==0 and cert.get("allowed_candidate_count")==cert.get("candidate_count")
        checks=cert.get("checks") or []
        allowed=sum(1 for x in checks if x.get("allowed"))
        return allowed==cert.get("allowed_candidate_count") and len(checks)==cert.get("candidate_count")
    checks=cert.get("checks") or {}
    status=cert.get("status")
    ok=bool(checks.get("permissions_ok") and checks.get("budget_ok") and checks.get("precedence_ok") and checks.get("replay_ok"))
    if status in {"CONTROLLABLE","REACHABLE_UNDER_OPEN_CONTROL_WORLD"}:
        return ok and cert.get("reachability")=="REACHABLE"
    if status=="IDENTIFIABLE_BUT_UNREACHABLE":
        return (not ok) and cert.get("reachability")=="UNREACHABLE"
    if status=="NO_ACTION_REQUIRED":
        return cert.get("requested_action_count")==0
    return False


def controllability_summary(firewall_cycles: list[dict[str,Any]], plan_cycles: list[dict[str,Any]], final_firewall: dict[str,Any] | None=None) -> dict[str,Any]:
    certs=[x.get("certificate") or {} for x in plan_cycles]
    blocked=sum(int(((x.get("certificate") or {}).get("blocked_candidate_count") or 0)) for x in firewall_cycles)
    return {"contract":"json-consistency-repair.repair-controllability-summary.v1","firewall_cycles":firewall_cycles,
            "control_plan_cycles":plan_cycles,"final_firewall":final_firewall,
            "blocked_candidate_observations":blocked,
            "reachable_plan_count":sum(1 for c in certs if c.get("reachability") in {"REACHABLE","NO_ACTION"}),
            "unreachable_plan_count":sum(1 for c in certs if c.get("reachability")=="UNREACHABLE")}
