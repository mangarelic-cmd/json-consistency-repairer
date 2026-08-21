from __future__ import annotations

from collections import defaultdict
from decimal import Decimal
from typing import Any
import hashlib
import json

from .exactmath import decimal_of, canonical_number_like


def stable_conservation_id(rule: dict[str, Any], prefix: str = "conservation") -> str:
    payload={k:v for k,v in rule.items() if k not in {"rule_id","confidence","support"}}
    raw=json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(",",":"),default=str).encode("utf-8")
    return f"{prefix}_{hashlib.sha256(raw).hexdigest()[:20]}"


def aggregate_target_hint(field: str, kind: str) -> bool:
    f=str(field).lower()
    if kind=="count":
        return f in {"count","item_count","line_count","row_count","number_of_items","number_of_lines"} or f.endswith("_count")
    return f in {"total","sum","subtotal","grand_total","amount_total","total_amount","total_value","total_quantity","quantity_total"} or f.endswith("_total") or f.endswith("_sum")


def sum_child_values(record: dict[str,Any], items_field: str, value_field: str) -> Decimal | None:
    items=record.get(items_field)
    if not isinstance(items,list): return None
    total=Decimal(0)
    for item in items:
        if not isinstance(item,dict): return None
        d=decimal_of(item.get(value_field))
        if d is None: return None
        total += d
    return total


def child_count(record: dict[str,Any], items_field: str) -> int | None:
    items=record.get(items_field)
    if not isinstance(items,list): return None
    return len(items)


def scalar_balance_residue(record: dict[str,Any], terms: list[dict[str,Any]]) -> Decimal | None:
    residue=Decimal(0)
    for term in terms:
        field=term.get("field")
        if not isinstance(field,str): return None
        d=decimal_of(record.get(field))
        if d is None: return None
        coeff=decimal_of(term.get("coefficient",1))
        if coeff is None: return None
        residue += coeff*d
    return residue


def scalar_balance_expected_target(record: dict[str,Any], terms: list[dict[str,Any]], target: str) -> Decimal | None:
    target_terms=[t for t in terms if t.get("field")==target]
    if len(target_terms)!=1: return None
    coeff=decimal_of(target_terms[0].get("coefficient",1))
    if coeff is None or coeff==0: return None
    other=Decimal(0)
    for term in terms:
        field=term.get("field")
        if field==target: continue
        if not isinstance(field,str): return None
        d=decimal_of(record.get(field)); c=decimal_of(term.get("coefficient",1))
        if d is None or c is None: return None
        other += c*d
    return -other/coeff


def multiset_map(items: Any, key_field: str, quantity_field: str) -> dict[str,Decimal] | None:
    if not isinstance(items,list): return None
    out: dict[str,Decimal]=defaultdict(lambda:Decimal(0))
    for item in items:
        if not isinstance(item,dict) or key_field not in item: return None
        key=item.get(key_field)
        if isinstance(key,(dict,list)) or key is None: return None
        q=decimal_of(item.get(quantity_field))
        if q is None: return None
        try: k=json.dumps(key,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False)
        except (TypeError,ValueError): return None
        out[k]+=q
    return dict(sorted(out.items()))


def multiset_residue(left: dict[str,Decimal], right: dict[str,Decimal]) -> dict[str,Decimal]:
    keys=sorted(set(left)|set(right))
    return {k:left.get(k,Decimal(0))-right.get(k,Decimal(0)) for k in keys if left.get(k,Decimal(0))!=right.get(k,Decimal(0))}


def _multiset_single_target_patch(record: dict[str,Any], rule: dict[str,Any]) -> tuple[str,int,Any,Any] | None:
    left_field=rule.get("left_field"); right_field=rule.get("right_field")
    key_field=rule.get("key_field"); quantity_field=rule.get("quantity_field")
    side=rule.get("target_side")
    if not all(isinstance(x,str) for x in (left_field,right_field,key_field,quantity_field)): return None
    left=multiset_map(record.get(left_field),key_field,quantity_field)
    right=multiset_map(record.get(right_field),key_field,quantity_field)
    if left is None or right is None: return None
    residue=multiset_residue(left,right)
    if len(residue)!=1: return None
    key_enc,delta=next(iter(residue.items()))
    target_field=right_field if side=="right" else left_field if side=="left" else None
    if target_field is None: return None
    items=record.get(target_field)
    if not isinstance(items,list): return None
    hits=[]
    for idx,item in enumerate(items):
        if not isinstance(item,dict): continue
        try: enc=json.dumps(item.get(key_field),ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False)
        except (TypeError,ValueError): continue
        if enc==key_enc: hits.append((idx,item))
    if len(hits)!=1: return None
    idx,item=hits[0]
    old=item.get(quantity_field); d=decimal_of(old)
    if d is None: return None
    # left-right = delta. Adjust right by +delta or left by -delta.
    expected=d+delta if side=="right" else d-delta
    return target_field,idx,old,canonical_number_like(expected,[old])


def evaluate_conservation_rule(record: dict[str,Any], rule: dict[str,Any]) -> dict[str,Any]:
    kind=rule.get("kind")
    if kind=="aggregate_sum":
        items=rule.get("items_field"); value=rule.get("value_field"); target=rule.get("target")
        if not all(isinstance(x,str) for x in (items,value,target)): return {"status":None,"reason":"invalid_rule"}
        expected=sum_child_values(record,items,value)
        if expected is None: return {"status":None,"reason":"insufficient_material"}
        actual=decimal_of(record.get(target))
        return {"status": actual==expected if actual is not None else False,"expected":expected,"actual":actual,"target":target,"residue":None if actual is None else actual-expected}
    if kind=="aggregate_count":
        items=rule.get("items_field"); target=rule.get("target")
        if not all(isinstance(x,str) for x in (items,target)): return {"status":None,"reason":"invalid_rule"}
        expected=child_count(record,items)
        if expected is None: return {"status":None,"reason":"insufficient_material"}
        actual=record.get(target)
        d=decimal_of(actual)
        ok=d is not None and d==Decimal(expected)
        return {"status":ok,"expected":Decimal(expected),"actual":d,"target":target,"residue":None if d is None else d-Decimal(expected)}
    if kind=="balance":
        terms=rule.get("terms"); target=rule.get("target")
        if not isinstance(terms,list) or not isinstance(target,str): return {"status":None,"reason":"invalid_rule"}
        residue=scalar_balance_residue(record,terms)
        if residue is None: return {"status":None,"reason":"insufficient_material"}
        expected=scalar_balance_expected_target(record,terms,target)
        return {"status":residue==0,"expected":expected,"actual":decimal_of(record.get(target)),"target":target,"residue":residue}
    if kind=="multiset_balance":
        lf,rf,kf,qf=(rule.get("left_field"),rule.get("right_field"),rule.get("key_field"),rule.get("quantity_field"))
        if not all(isinstance(x,str) for x in (lf,rf,kf,qf)): return {"status":None,"reason":"invalid_rule"}
        left=multiset_map(record.get(lf),kf,qf); right=multiset_map(record.get(rf),kf,qf)
        if left is None or right is None: return {"status":None,"reason":"insufficient_material"}
        residue=multiset_residue(left,right)
        patch=_multiset_single_target_patch(record,rule)
        return {"status":not residue,"residue":{k:format(v,'f') for k,v in residue.items()},"single_target_patch":patch}
    return {"status":None,"reason":"unknown_rule_kind"}


def conservation_rule_patch(record: dict[str,Any], rule: dict[str,Any]) -> dict[str,Any] | None:
    ev=evaluate_conservation_rule(record,rule)
    if ev.get("status") is not False: return None
    kind=rule.get("kind")
    if kind in {"aggregate_sum","aggregate_count","balance"}:
        target=ev.get("target"); expected=ev.get("expected")
        if not isinstance(target,str) or expected is None: return None
        old=record.get(target)
        examples=[old] if old is not None else []
        new=canonical_number_like(expected,examples)
        return {"path_field":target,"old_value":old,"new_value":new,"add_if_missing":target not in record}
    if kind=="multiset_balance":
        p=ev.get("single_target_patch")
        if p is None: return None
        field,idx,old,new=p
        return {"path_parts":[field,idx,rule["quantity_field"]],"old_value":old,"new_value":new,"add_if_missing":False}
    return None
