"""PASS031 — robust uncertainty / clock / regime / hysteresis envelopes.

This layer is deliberately a *firewall*, not another heuristic repairer.  It
examines already-proposed candidates and rejects any mutation whose validity
cannot survive the explicitly declared admissible envelope.

No wall clock is read.  Time rules require an explicit evaluation_time.
"""
from __future__ import annotations
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any
import hashlib, json

from .models import AnalysisResult, Candidate, Issue, digest
from .tree import get, decode_pointer
from .models import pointer
from .exactmath import decimal_of

CONTRACT = "json-consistency-repair.robust-envelope.v1"
FIREWALL_CONTRACT = "json-consistency-repair.robust-envelope-firewall.v1"


def _sha(v: Any) -> str:
    return hashlib.sha256(json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _safe_get(root: Any, path: str | None):
    if not isinstance(path, str): return False, None
    try: return True, get(root, path)
    except Exception: return False, None


def _dec(v: Any) -> Decimal | None:
    return decimal_of(v)


def _pattern_bindings(pattern: str, path: str) -> list[str] | None:
    try: pt=decode_pointer(pattern); xt=decode_pointer(path)
    except Exception: return None
    if len(pt)!=len(xt): return None
    bindings=[]
    for a,b in zip(pt,xt):
        if a=="*": bindings.append(b)
        elif a!=b: return None
    return bindings

def _resolve_template_path(template: str, bindings: list[str]) -> str | None:
    try: toks=decode_pointer(template)
    except Exception: return None
    out=[]; bi=0
    for tok in toks:
        if tok=="*":
            if bi>=len(bindings): return None
            out.append(bindings[bi]); bi+=1
        else: out.append(tok)
    return pointer(out)

def _resolved_rule(rule: dict[str, Any], candidate_path: str) -> dict[str, Any]:
    pat=rule.get("path_pattern")
    if not isinstance(pat,str): return rule
    bindings=_pattern_bindings(pat,candidate_path)
    if bindings is None: return rule
    row=deepcopy(rule)
    for key,val in list(row.items()):
        if isinstance(val,str) and (key in {"path","path_prefix","center_path","lower_path","upper_path","radius_path","sigma_path","timestamp_path","regime_path","state_path","metric_path","uncertainty_radius_path"}):
            if "*" in val:
                rv=_resolve_template_path(val,bindings)
                if rv is not None: row[key]=rv
    return row

def _path_matches(candidate_path: str, rule: dict[str, Any]) -> bool:
    pattern=rule.get("path_pattern")
    if isinstance(pattern,str): return _pattern_bindings(pattern,candidate_path) is not None
    exact = rule.get("path")
    prefix = rule.get("path_prefix")
    if isinstance(exact, str) and candidate_path != exact: return False
    if isinstance(prefix, str) and not (candidate_path == prefix or candidate_path.startswith(prefix.rstrip("/") + "/")): return False
    return isinstance(exact, str) or isinstance(prefix, str)


def _parse_time(v: Any) -> datetime | None:
    if not isinstance(v, str) or not v.strip(): return None
    s=v.strip()
    if s.endswith("Z"): s=s[:-1]+"+00:00"
    try: dt=datetime.fromisoformat(s)
    except ValueError: return None
    if dt.tzinfo is None: return None
    return dt.astimezone(timezone.utc)


def _uncertainty_interval(root: Any, rule: dict[str, Any]) -> tuple[Decimal | None, Decimal | None, dict[str, Any]]:
    center_path=rule.get("center_path") or rule.get("path")
    okc,cv=_safe_get(root,center_path); center=_dec(cv) if okc else None
    lo=hi=None; source=None
    if isinstance(rule.get("lower_path"),str) and isinstance(rule.get("upper_path"),str):
        okl,lv=_safe_get(root,rule["lower_path"]); oku,uv=_safe_get(root,rule["upper_path"])
        lo=_dec(lv) if okl else None; hi=_dec(uv) if oku else None; source="explicit_bounds"
    elif isinstance(rule.get("radius_path"),str) and center is not None:
        okr,rv=_safe_get(root,rule["radius_path"]); rad=_dec(rv) if okr else None
        if rad is not None and rad >= 0: lo=center-rad; hi=center+rad; source="radius"
    elif isinstance(rule.get("sigma_path"),str) and center is not None:
        oks,sv=_safe_get(root,rule["sigma_path"]); sigma=_dec(sv) if oks else None
        k=_dec(rule.get("k",1))
        if sigma is not None and k is not None and sigma >= 0 and k >= 0:
            lo=center-k*sigma; hi=center+k*sigma; source="sigma"
    elif center is not None and (rule.get("radius") is not None or rule.get("sigma") is not None):
        if rule.get("radius") is not None:
            rad=_dec(rule.get("radius"))
            if rad is not None and rad >= 0: lo=center-rad; hi=center+rad; source="literal_radius"
        else:
            sigma=_dec(rule.get("sigma")); k=_dec(rule.get("k",1))
            if sigma is not None and k is not None and sigma >= 0 and k >= 0:
                lo=center-k*sigma; hi=center+k*sigma; source="literal_sigma"
    return lo,hi,{"center_path":center_path,"center":str(center) if center is not None else None,"source":source,
                  "lower":str(lo) if lo is not None else None,"upper":str(hi) if hi is not None else None}


def _eval_uncertainty(root: Any, c: Candidate, rule: dict[str, Any]) -> dict[str, Any]:
    lo,hi,meta=_uncertainty_interval(root,rule); nv=_dec(c.new_value)
    if lo is None or hi is None or nv is None:
        return {"allow":False,"reason":"UNCERTAINTY_ENVELOPE_UNRESOLVED",**meta}
    if lo>hi:
        return {"allow":False,"reason":"UNCERTAINTY_ENVELOPE_CONTRADICTION",**meta}
    # A point repair inside the currently admissible interval is not robustly identifiable.
    if lo <= nv <= hi:
        return {"allow":False,"reason":"CANDIDATE_WITHIN_ADMISSIBLE_UNCERTAINTY",**meta,"candidate":str(nv)}
    return {"allow":True,"reason":"CANDIDATE_SEPARATED_FROM_ADMISSIBLE_UNCERTAINTY",**meta,"candidate":str(nv)}


def _eval_clock(root: Any, c: Candidate, rule: dict[str, Any]) -> dict[str, Any]:
    evt_path=rule.get("timestamp_path")
    oke,ev=_safe_get(root,evt_path); event=_parse_time(ev) if oke else None
    evaluation=_parse_time(rule.get("evaluation_time"))
    if evaluation is None:
        return {"allow":False,"reason":"CLOCK_EVALUATION_TIME_REQUIRED","timestamp_path":evt_path}
    if event is None:
        return {"allow":False,"reason":"CLOCK_TIMESTAMP_UNRESOLVED","timestamp_path":evt_path,"evaluation_time":evaluation.isoformat()}
    age=(evaluation-event).total_seconds()
    max_age=_dec(rule.get("max_age_seconds")); max_future=_dec(rule.get("max_future_skew_seconds",0))
    if max_age is None or max_age < 0 or max_future is None or max_future < 0:
        return {"allow":False,"reason":"CLOCK_RULE_INVALID","age_seconds":age}
    authoritative=bool((c.metadata or {}).get("authority_proof_sha256"))
    allow_auth=bool(rule.get("allow_authoritative_when_stale",False))
    if Decimal(str(age)) > max_age:
        if authoritative and allow_auth:
            return {"allow":True,"reason":"STALE_BUT_SCOPED_AUTHORITY_ALLOWED","age_seconds":age,"max_age_seconds":str(max_age)}
        return {"allow":False,"reason":"STALE_OBSERVATION_GATE","age_seconds":age,"max_age_seconds":str(max_age)}
    if Decimal(str(age)) < -max_future:
        return {"allow":False,"reason":"FUTURE_SKEW_GATE","age_seconds":age,"max_future_skew_seconds":str(max_future)}
    return {"allow":True,"reason":"CLOCK_WITHIN_ADMISSIBLE_WINDOW","age_seconds":age,"max_age_seconds":str(max_age),"max_future_skew_seconds":str(max_future)}


def _eval_regime(root: Any, c: Candidate, rule: dict[str, Any]) -> dict[str, Any]:
    rp=rule.get("regime_path"); ok,rv=_safe_get(root,rp)
    if not ok:
        return {"allow":False,"reason":"REGIME_UNRESOLVED","regime_path":rp}
    allowed=rule.get("allowed_values")
    if isinstance(allowed,list) and rv not in allowed:
        return {"allow":False,"reason":"REGIME_OUTSIDE_DECLARED_DOMAIN","regime_path":rp,"regime_value":rv}
    key=str(rule.get("candidate_metadata_key") or "regime_value")
    bound=(c.metadata or {}).get(key)
    if bool(rule.get("require_candidate_regime",True)) and bound is None:
        return {"allow":False,"reason":"CANDIDATE_NOT_REGIME_BOUND","regime_path":rp,"regime_value":rv,"metadata_key":key}
    if bound is not None and bound != rv:
        return {"allow":False,"reason":"CROSS_REGIME_CANDIDATE_GATE","regime_path":rp,"regime_value":rv,"candidate_regime":bound}
    return {"allow":True,"reason":"REGIME_MATCH","regime_path":rp,"regime_value":rv,"candidate_regime":bound}


def _eval_hysteresis(root: Any, c: Candidate, rule: dict[str, Any]) -> dict[str, Any]:
    state_path=rule.get("state_path"); metric_path=rule.get("metric_path")
    oks,state=_safe_get(root,state_path); okm,mv=_safe_get(root,metric_path); metric=_dec(mv) if okm else None
    if not oks or metric is None:
        return {"allow":False,"reason":"HYSTERESIS_STATE_OR_METRIC_UNRESOLVED","state_path":state_path,"metric_path":metric_path}
    on=rule.get("on_value","ON"); off=rule.get("off_value","OFF")
    enter=_dec(rule.get("enter_above")); exitv=_dec(rule.get("exit_below"))
    if enter is None or exitv is None or exitv>enter:
        return {"allow":False,"reason":"HYSTERESIS_RULE_INVALID","enter_above":str(enter) if enter is not None else None,"exit_below":str(exitv) if exitv is not None else None}
    # Optional uncertainty widens the metric point into [lo,hi].
    rad=None
    if isinstance(rule.get("uncertainty_radius_path"),str):
        okr,rv=_safe_get(root,rule.get("uncertainty_radius_path")); rad=_dec(rv) if okr else None
    elif rule.get("uncertainty_radius") is not None:
        rad=_dec(rule.get("uncertainty_radius"))
    if rad is None: rad=Decimal(0)
    if rad<0: return {"allow":False,"reason":"HYSTERESIS_UNCERTAINTY_INVALID"}
    lo,hi=metric-rad,metric+rad
    if c.path != state_path:
        return {"allow":True,"reason":"HYSTERESIS_RULE_NOT_STATE_TARGET"}
    if state==off and c.new_value==on:
        allow=lo>=enter
        return {"allow":allow,"reason":"HYSTERESIS_ENTER_CERTIFIED" if allow else "HYSTERESIS_ENTER_NOT_ROBUST",
                "metric_lower":str(lo),"metric_upper":str(hi),"enter_above":str(enter),"state":state,"candidate_state":c.new_value}
    if state==on and c.new_value==off:
        allow=hi<=exitv
        return {"allow":allow,"reason":"HYSTERESIS_EXIT_CERTIFIED" if allow else "HYSTERESIS_EXIT_NOT_ROBUST",
                "metric_lower":str(lo),"metric_upper":str(hi),"exit_below":str(exitv),"state":state,"candidate_state":c.new_value}
    if c.new_value==state:
        return {"allow":True,"reason":"HYSTERESIS_NO_STATE_CHANGE","state":state}
    return {"allow":False,"reason":"HYSTERESIS_UNDECLARED_TRANSITION","state":state,"candidate_state":c.new_value}


def _evaluate(root: Any, c: Candidate, rule: dict[str, Any]) -> dict[str, Any]:
    rr=_resolved_rule(rule,c.path)
    kind=str(rr.get("kind") or "")
    if kind=="uncertainty_interval": return _eval_uncertainty(root,c,rr)
    if kind=="clock_freshness": return _eval_clock(root,c,rr)
    if kind=="regime_guard": return _eval_regime(root,c,rr)
    if kind=="hysteresis": return _eval_hysteresis(root,c,rr)
    return {"allow":False,"reason":"UNKNOWN_ROBUST_ENVELOPE_KIND"}


def normalize_rules(config) -> tuple[dict[str, Any], ...]:
    rules=[]
    doc=getattr(config,"logic_document",None) or getattr(config,"system_document",None) or getattr(config,"moment_document",None)
    for i,raw in enumerate(getattr(config,"robust_envelope_rules",()) or ()):
        if not isinstance(raw,dict): continue
        if raw.get("document") not in (None,"",doc,"@stream"): continue
        row=deepcopy(raw); row.setdefault("rule_id",f"robust-{i:04d}")
        row["rule_sha256"]=_sha({k:v for k,v in row.items() if k!="rule_sha256"})
        rules.append(row)
    return tuple(rules)


def apply_robust_envelope_firewall(root: Any, analysis: AnalysisResult, config) -> tuple[AnalysisResult, dict[str, Any]]:
    rules=normalize_rules(config)
    if not rules:
        cert={"contract":FIREWALL_CONTRACT,"enabled":False,"rule_count":0,"candidate_count_before":len(analysis.candidates),
              "candidate_count_after":len(analysis.candidates),"gated_count":0,"decisions":[]}
        cert["certificate_sha256"]=_sha(cert)
        return analysis,cert
    kept=[]; decisions=[]; blocked_keys=set()
    for c in analysis.candidates:
        matching=[r for r in rules if _path_matches(c.path,r) or (r.get("kind")=="hysteresis" and c.path==r.get("state_path"))]
        if not matching:
            kept.append(c); continue
        rows=[]; allow=True
        for r in matching:
            ev=_evaluate(root,c,r); ev={"rule_id":r.get("rule_id"),"rule_sha256":r.get("rule_sha256"),"kind":r.get("kind"),**ev}
            rows.append(ev)
            if not ev.get("allow"): allow=False
        decision={"candidate_id":c.candidate_id,"analyzer":c.analyzer,"path":c.path,"new_value_digest":digest(c.new_value),
                  "allow":allow,"evaluations":rows}
        decision["decision_sha256"]=_sha(decision)
        decisions.append(decision)
        if allow:
            meta={**(c.metadata or {}),"robust_envelope_decision_sha256":decision["decision_sha256"],"robust_envelope_contract":FIREWALL_CONTRACT}
            kept.append(replace(c,metadata=meta))
        else:
            blocked_keys.add((c.analyzer,c.path))
    # If every candidate for an issue analyzer/path was gated, make that issue explicitly non-repairable.
    remaining_keys={(c.analyzer,c.path) for c in kept}
    issues=[]
    bydecision={(d["analyzer"],d["path"]):d for d in decisions if not d.get("allow")}
    for i in analysis.issues:
        key=(i.analyzer,i.path)
        if key in blocked_keys and key not in remaining_keys:
            d=bydecision.get(key)
            md={**(i.metadata or {}),"robust_envelope_gate":True,
                "robust_envelope_decision_sha256":d.get("decision_sha256") if d else None}
            issues.append(replace(i,repairable=False,metadata=md))
        else: issues.append(i)
    cert={"contract":FIREWALL_CONTRACT,"enabled":True,"rule_count":len(rules),"rules":list(rules),
          "candidate_count_before":len(analysis.candidates),"candidate_count_after":len(kept),
          "gated_count":len(analysis.candidates)-len(kept),"decisions":sorted(decisions,key=lambda d:d["candidate_id"])}
    cert["certificate_sha256"]=_sha(cert)
    return AnalysisResult(issues,kept,list(analysis.relations)),cert


def robust_envelope_summary(cycles: list[dict[str, Any]], final: dict[str, Any] | None=None) -> dict[str, Any]:
    rows=[x for x in cycles if isinstance(x,dict)]
    certs=[x.get("certificate") or x for x in rows]
    return {"contract":"json-consistency-repair.robust-envelope-summary.v1",
            "enabled":any(bool(c.get("enabled")) for c in certs if isinstance(c,dict)),
            "cycle_count":len(rows),
            "gated_count":sum(int((c or {}).get("gated_count",0)) for c in certs),
            "final_gated_count":int((final or {}).get("gated_count",0)),
            "final_certificate_sha256":(final or {}).get("certificate_sha256")}


def verify_robust_envelope_certificate(cert: dict[str, Any]) -> bool:
    if not isinstance(cert,dict) or cert.get("contract")!=FIREWALL_CONTRACT: return False
    supplied=cert.get("certificate_sha256")
    if not isinstance(supplied,str): return False
    row=deepcopy(cert); row.pop("certificate_sha256",None)
    if _sha(row)!=supplied: return False
    for r in cert.get("rules") or []:
        if not isinstance(r,dict) or not r.get("rule_sha256"): return False
        rr=deepcopy(r); rs=rr.pop("rule_sha256",None)
        if _sha(rr)!=rs: return False
    for d in cert.get("decisions") or []:
        if not isinstance(d,dict) or not d.get("decision_sha256"): return False
        dd=deepcopy(d); ds=dd.pop("decision_sha256",None)
        if _sha(dd)!=ds: return False
        if any(not isinstance(e,dict) or not e.get("rule_sha256") for e in d.get("evaluations") or []): return False
    return True
