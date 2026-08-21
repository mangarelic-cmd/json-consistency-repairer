from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import ast
import hashlib
import json
import math
from typing import Any, Iterable

from .models import AnalysisResult, Candidate, Issue, pointer
from .linear_exact import constraint_object_arrays, native

CONTRACT = "json-consistency-repair.typed-expression-ir.v1"
RULE_CONTRACT = "json-consistency-repair.typed-expression-rule.v1"


class ExpressionIRException(ValueError):
    pass


@dataclass(frozen=True)
class EvalResult:
    status: str
    value: Any = None
    value_type: str | None = None
    reason: str | None = None


def _canon(v: Any) -> bytes:
    return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _rid(rule: dict[str, Any]) -> str:
    payload = {k: v for k, v in rule.items() if k not in {"rule_id", "semantic_claim_provenance"}}
    return "expr_" + hashlib.sha256(_canon(payload)).hexdigest()[:20]


def _fraction(v: Any) -> Fraction | None:
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, Fraction):
        return v
    if isinstance(v, int):
        return Fraction(v)
    if isinstance(v, float):
        if not math.isfinite(v):
            return None
        return Fraction(str(v))
    if isinstance(v, str):
        try:
            return Fraction(v)
        except Exception:
            return None
    return None


def _type_of(v: Any) -> str:
    if isinstance(v, bool): return "boolean"
    if isinstance(v, int) and not isinstance(v, bool): return "integer"
    if isinstance(v, Fraction): return "integer" if v.denominator == 1 else "rational"
    if isinstance(v, float): return "number"
    if isinstance(v, str): return "string"
    if v is None: return "null"
    if isinstance(v, list): return "array"
    if isinstance(v, dict): return "object"
    return type(v).__name__


def _const_node(value: Any) -> dict[str, Any]:
    q = _fraction(value)
    if q is not None and not isinstance(value, str):
        return {"op": "const", "value": str(q), "value_type": "integer" if q.denominator == 1 else "rational"}
    return {"op": "const", "value": value, "value_type": _type_of(value)}


def _attribute_name(node: ast.AST) -> str | None:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def parse_expression(text: str) -> dict[str, Any]:
    """Parse a deliberately small exact expression language into canonical JSON IR.

    Supported operators: +, -, *, /, integer **, abs, min, max, floor, ceil,
    sqrt, mod, sum and product. Names (including dotted names) denote record fields.
    No attribute lookup, arbitrary call, indexing, comprehension, or Python execution occurs.
    """
    try:
        tree = ast.parse(text, mode="eval")
    except SyntaxError as exc:
        raise ExpressionIRException(f"invalid expression syntax: {text!r}") from exc

    def cv(node: ast.AST) -> dict[str, Any]:
        if isinstance(node, ast.Name):
            return {"op": "field", "name": node.id, "value_type": "dynamic"}
        if isinstance(node, ast.Attribute):
            name = _attribute_name(node)
            if not name:
                raise ExpressionIRException("unsupported attribute expression")
            return {"op": "field", "name": name, "value_type": "dynamic"}
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
                seg = ast.get_source_segment(text, node)
                try:
                    q = Fraction(seg) if seg is not None else Fraction(str(node.value))
                except Exception as exc:
                    raise ExpressionIRException("invalid numeric literal") from exc
                return {"op": "const", "value": str(q), "value_type": "integer" if q.denominator == 1 else "rational"}
            if isinstance(node.value, (str, bool)) or node.value is None:
                return _const_node(node.value)
            raise ExpressionIRException("unsupported literal")
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            child = cv(node.operand)
            if isinstance(node.op, ast.UAdd): return child
            return {"op": "neg", "args": [child], "value_type": "number"}
        if isinstance(node, ast.BinOp):
            amap = {ast.Add: "add", ast.Sub: "sub", ast.Mult: "mul", ast.Div: "div"}
            for cls, op in amap.items():
                if isinstance(node.op, cls):
                    return {"op": op, "args": [cv(node.left), cv(node.right)], "value_type": "number"}
            if isinstance(node.op, ast.Pow):
                right = cv(node.right)
                if right.get("op") != "const":
                    raise ExpressionIRException("power exponent must be an exact integer literal")
                q = _fraction(right.get("value"))
                if q is None or q.denominator != 1:
                    raise ExpressionIRException("power exponent must be an exact integer literal")
                return {"op": "pow_int", "args": [cv(node.left)], "exponent": int(q), "value_type": "number"}
            if isinstance(node.op, ast.Mod):
                return {"op": "mod", "args": [cv(node.left), cv(node.right)], "value_type": "integer"}
            raise ExpressionIRException("unsupported binary operator")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            name = node.func.id
            if node.keywords:
                raise ExpressionIRException("keyword arguments are not supported")
            args = [cv(x) for x in node.args]
            if name in {"abs", "floor", "ceil", "sqrt"} and len(args) == 1:
                return {"op": name, "args": args, "value_type": "integer" if name in {"floor", "ceil"} else "number"}
            if name in {"min", "max"} and len(args) >= 2:
                return {"op": name, "args": args, "value_type": "number"}
            if name == "mod" and len(args) == 2:
                return {"op": "mod", "args": args, "value_type": "integer"}
            if name == "sum" and len(args) >= 1:
                return {"op": "add", "args": args, "value_type": "number"}
            if name == "product" and len(args) >= 1:
                return {"op": "mul", "args": args, "value_type": "number"}
            raise ExpressionIRException(f"unsupported function {name!r}")
        raise ExpressionIRException(f"unsupported expression node: {type(node).__name__}")

    return normalize_expression(cv(tree.body))


def normalize_expression(node: Any) -> dict[str, Any]:
    if isinstance(node, str):
        return parse_expression(node)
    if not isinstance(node, dict):
        return _const_node(node)
    op = str(node.get("op") or "")
    if op == "field":
        name = str(node.get("name") or "")
        if not name:
            raise ExpressionIRException("field node requires name")
        return {"op": "field", "name": name, "value_type": str(node.get("value_type") or "dynamic")}
    if op == "const":
        val = node.get("value")
        typ = str(node.get("value_type") or _type_of(val))
        if typ in {"integer", "rational", "number"}:
            q = _fraction(val)
            if q is None:
                raise ExpressionIRException("numeric const is not exact")
            return {"op": "const", "value": str(q), "value_type": "integer" if q.denominator == 1 else "rational"}
        return {"op": "const", "value": val, "value_type": typ}
    args = [normalize_expression(x) for x in (node.get("args") or [])]
    if op in {"neg", "abs", "floor", "ceil", "sqrt"} and len(args) != 1:
        raise ExpressionIRException(f"{op} requires one argument")
    if op in {"sub", "div", "mod"} and len(args) != 2:
        raise ExpressionIRException(f"{op} requires two arguments")
    if op in {"add", "mul", "min", "max"} and not args:
        raise ExpressionIRException(f"{op} requires arguments")
    if op == "pow_int":
        if len(args) != 1:
            raise ExpressionIRException("pow_int requires one argument")
        exp = node.get("exponent")
        if isinstance(exp, bool) or not isinstance(exp, int):
            raise ExpressionIRException("pow_int exponent must be integer")
        return {"op": op, "args": args, "exponent": exp, "value_type": "number"}
    if op not in {"neg", "add", "sub", "mul", "div", "abs", "min", "max", "floor", "ceil", "sqrt", "mod"}:
        raise ExpressionIRException(f"unsupported op {op!r}")
    typ = "integer" if op in {"floor", "ceil", "mod"} else "number"
    return {"op": op, "args": args, "value_type": typ}


def expression_fields(node: dict[str, Any]) -> tuple[str, ...]:
    out: set[str] = set()
    def rec(n: dict[str, Any]):
        if n.get("op") == "field": out.add(str(n.get("name")))
        for a in n.get("args") or []: rec(a)
    rec(node)
    return tuple(sorted(out))


def expression_operators(node: dict[str, Any]) -> tuple[str, ...]:
    out: set[str] = set()
    def rec(n: dict[str, Any]):
        out.add(str(n.get("op")))
        for a in n.get("args") or []: rec(a)
    rec(node)
    return tuple(sorted(out))


def _int_nth_root_exact(value: Fraction, n: int) -> Fraction | None:
    if n <= 0:
        return None
    if value < 0 and n % 2 == 0:
        return None
    sign = -1 if value < 0 else 1
    num = abs(value.numerator); den = value.denominator
    # Integer root without floating approximation.
    def root_int(x: int) -> int | None:
        if x in {0, 1}: return x
        lo, hi = 0, 1
        while hi ** n < x: hi *= 2
        while lo <= hi:
            mid = (lo + hi) // 2; p = mid ** n
            if p == x: return mid
            if p < x: lo = mid + 1
            else: hi = mid - 1
        return None
    rn = root_int(num); rd = root_int(den)
    if rn is None or rd is None: return None
    return Fraction(sign * rn, rd)


def evaluate_expression(node: dict[str, Any], row: dict[str, Any]) -> EvalResult:
    op = node.get("op")
    if op == "field":
        name = str(node.get("name"))
        if name not in row or row.get(name) is None:
            return EvalResult("UNKNOWN", reason=f"missing field {name}")
        v = row.get(name)
        return EvalResult("VALUE", v, _type_of(v))
    if op == "const":
        typ = node.get("value_type")
        if typ in {"integer", "rational", "number"}:
            q = _fraction(node.get("value"))
            return EvalResult("VALUE", q, "integer" if q is not None and q.denominator == 1 else "rational") if q is not None else EvalResult("DOMAIN_ERROR", reason="invalid exact numeric constant")
        return EvalResult("VALUE", node.get("value"), str(typ))
    vals = [evaluate_expression(a, row) for a in node.get("args") or []]
    if any(v.status == "DOMAIN_ERROR" for v in vals):
        return next(v for v in vals if v.status == "DOMAIN_ERROR")
    if any(v.status != "VALUE" for v in vals):
        return EvalResult("UNKNOWN", reason="operand unknown")
    if op == "neg":
        q = _fraction(vals[0].value)
        return EvalResult("VALUE", -q, "number") if q is not None else EvalResult("DOMAIN_ERROR", reason="neg requires number")
    qs = [_fraction(v.value) for v in vals]
    if op in {"add", "sub", "mul", "div", "pow_int", "abs", "min", "max", "floor", "ceil", "sqrt", "mod"} and any(q is None for q in qs):
        return EvalResult("DOMAIN_ERROR", reason=f"{op} requires exact numeric operands")
    try:
        if op == "add":
            z = sum(qs, Fraction(0)); return EvalResult("VALUE", z, "number")
        if op == "sub": return EvalResult("VALUE", qs[0] - qs[1], "number")
        if op == "mul":
            z = Fraction(1)
            for q in qs: z *= q
            return EvalResult("VALUE", z, "number")
        if op == "div":
            if qs[1] == 0: return EvalResult("DOMAIN_ERROR", reason="division by zero")
            return EvalResult("VALUE", qs[0] / qs[1], "number")
        if op == "pow_int":
            n = int(node.get("exponent")); q = qs[0]
            if n < 0 and q == 0: return EvalResult("DOMAIN_ERROR", reason="zero to negative power")
            return EvalResult("VALUE", q ** n, "number")
        if op == "abs": return EvalResult("VALUE", abs(qs[0]), "number")
        if op == "min": return EvalResult("VALUE", min(qs), "number")
        if op == "max": return EvalResult("VALUE", max(qs), "number")
        if op == "floor": return EvalResult("VALUE", Fraction(qs[0].numerator // qs[0].denominator), "integer")
        if op == "ceil": return EvalResult("VALUE", Fraction(-((-qs[0].numerator) // qs[0].denominator)), "integer")
        if op == "sqrt":
            if qs[0] < 0: return EvalResult("DOMAIN_ERROR", reason="sqrt of negative")
            rt = _int_nth_root_exact(qs[0], 2)
            return EvalResult("VALUE", rt, "number") if rt is not None else EvalResult("DOMAIN_ERROR", reason="sqrt is not exact rational")
        if op == "mod":
            if qs[0].denominator != 1 or qs[1].denominator != 1 or qs[1] == 0:
                return EvalResult("DOMAIN_ERROR", reason="mod requires integers and nonzero modulus")
            return EvalResult("VALUE", Fraction(int(qs[0]) % int(qs[1])), "integer")
    except (ArithmeticError, OverflowError, ValueError) as exc:
        return EvalResult("DOMAIN_ERROR", reason=str(exc))
    return EvalResult("DOMAIN_ERROR", reason=f"unsupported op {op}")


def _count_target(node: dict[str, Any], target: str) -> int:
    n = 1 if node.get("op") == "field" and node.get("name") == target else 0
    for a in node.get("args") or []: n += _count_target(a, target)
    return n


def _eval_numeric(node: dict[str, Any], row: dict[str, Any]) -> Fraction | None:
    e = evaluate_expression(node, row)
    return _fraction(e.value) if e.status == "VALUE" else None


def _invert(node: dict[str, Any], target: str, desired: Fraction, row: dict[str, Any]) -> tuple[str, Fraction | None, str | None]:
    if node.get("op") == "field":
        return ("UNIQUE", desired, None) if node.get("name") == target else ("NONE", None, "target mismatch")
    count = _count_target(node, target)
    if count != 1:
        return ("MULTIPLE" if count > 1 else "NONE", None, "target occurrence count is not one")
    op = node.get("op"); args = node.get("args") or []
    idx = next(i for i, a in enumerate(args) if _count_target(a, target)) if args else -1
    child = args[idx] if idx >= 0 else None
    others = [a for i, a in enumerate(args) if i != idx]
    ov = [_eval_numeric(a, row) for a in others]
    if any(v is None for v in ov): return "UNKNOWN", None, "non-target operand unknown"
    if op == "neg": return _invert(child, target, -desired, row)
    if op == "add": return _invert(child, target, desired - sum(ov, Fraction(0)), row)
    if op == "sub":
        if idx == 0: return _invert(child, target, desired + ov[0], row)
        left = _eval_numeric(args[0], row)
        return ("UNKNOWN", None, "left operand unknown") if left is None else _invert(child, target, left - desired, row)
    if op == "mul":
        p = Fraction(1)
        for v in ov: p *= v
        if p == 0:
            return ("MULTIPLE", None, "zero multiplier makes inverse non-unique") if desired == 0 else ("NONE", None, "inconsistent zero multiplier")
        return _invert(child, target, desired / p, row)
    if op == "div":
        if idx == 0:
            den = ov[0]
            if den == 0: return "NONE", None, "division denominator zero"
            return _invert(child, target, desired * den, row)
        num = _eval_numeric(args[0], row)
        if num is None: return "UNKNOWN", None, "numerator unknown"
        if desired == 0:
            return ("MULTIPLE", None, "zero quotient does not uniquely identify denominator") if num == 0 else ("NONE", None, "nonzero numerator cannot yield exact zero quotient")
        val = num / desired
        if val == 0: return "NONE", None, "denominator cannot be zero"
        return _invert(child, target, val, row)
    if op == "pow_int":
        n = int(node.get("exponent"))
        if n == 1: return _invert(child, target, desired, row)
        if n == 0: return "MULTIPLE", None, "zeroth power erases target"
        if n < 0:
            if desired == 0: return "NONE", None, "negative power cannot equal zero"
            desired = Fraction(1, 1) / desired; n = -n
        if n % 2 == 0 and desired != 0:
            return "MULTIPLE", None, "even power has sign symmetry"
        rt = _int_nth_root_exact(desired, n)
        if rt is None: return "NONE", None, "no exact rational inverse root"
        return _invert(child, target, rt, row)
    if op == "sqrt":
        if desired < 0: return "NONE", None, "sqrt output cannot be negative"
        return _invert(child, target, desired * desired, row)
    if op == "abs":
        if desired < 0: return "NONE", None, "absolute value cannot be negative"
        if desired == 0: return _invert(child, target, Fraction(0), row)
        return "MULTIPLE", None, "absolute value has sign symmetry"
    if op in {"min", "max", "floor", "ceil", "mod"}:
        return "MULTIPLE", None, f"{op} is not uniquely invertible without extra bounds"
    return "UNKNOWN", None, f"unsupported inverse for {op}"


def solve_equation(lhs: dict[str, Any], rhs: dict[str, Any], target: str, row: dict[str, Any]) -> tuple[str, Fraction | None, str | None]:
    lc = _count_target(lhs, target); rc = _count_target(rhs, target)
    if lc + rc == 0: return "NONE", None, "target absent"
    if lc and rc: return "MULTIPLE", None, "target occurs on both sides"
    if lc != 1 and rc != 1: return "MULTIPLE", None, "target occurrence is not unique"
    if lc:
        desired = _eval_numeric(rhs, row)
        if desired is None: return "UNKNOWN", None, "right side unknown"
        return _invert(lhs, target, desired, row)
    desired = _eval_numeric(lhs, row)
    if desired is None: return "UNKNOWN", None, "left side unknown"
    return _invert(rhs, target, desired, row)


def compile_expression_rule(rule: dict[str, Any]) -> dict[str, Any]:
    if rule.get("kind") != "expression": raise ExpressionIRException("rule kind must be expression")
    lhs = normalize_expression(rule.get("lhs")); rhs = normalize_expression(rule.get("rhs"))
    fields = sorted(set(expression_fields(lhs)) | set(expression_fields(rhs)))
    if rule.get("solve_for"):
        solve_for = list(rule.get("solve_for") or ())
        orientation = "EXPLICIT_SOLVE_FOR"
    elif lhs.get("op") == "field" and _count_target(rhs, str(lhs.get("name"))) == 0:
        # DSL/formula convention: a bare field on the left is an explicitly oriented output.
        # Non-bare equations remain symmetric and therefore expose every potentially invertible field.
        solve_for = [str(lhs.get("name"))]
        orientation = "BARE_LHS_OUTPUT"
    else:
        solve_for = list(fields)
        orientation = "SYMMETRIC_EQUATION"
    if any(str(x) not in fields for x in solve_for): raise ExpressionIRException("solve_for field not present in expression")
    out = {
        "contract": RULE_CONTRACT,
        "kind": "expression",
        "rule_id": str(rule.get("rule_id") or _rid(rule)),
        "name": rule.get("name"),
        "array_path": str(rule.get("array_path") or ""),
        "lhs": lhs, "rhs": rhs,
        "fields": fields,
        "solve_for": sorted(str(x) for x in solve_for),
        "orientation": orientation,
        "operators": sorted(set(expression_operators(lhs)) | set(expression_operators(rhs))),
        "exact": True,
    }
    out["rule_sha256"] = hashlib.sha256(_canon(out)).hexdigest()
    return out




def _native_exact_value(value: Any, old: Any = None) -> tuple[bool, Any]:
    """Project an exact expression value into JSON without inventing an approximation.

    Fractions whose denominator has factors other than 2 and 5 have no finite decimal JSON
    representation. They are allowed only when the existing carrier is a string, in which case
    the exact rational string is preserved.
    """
    if not isinstance(value, Fraction):
        if value is None or isinstance(value, (bool, int, float, str)):
            return True, value
        return False, None
    if value.denominator == 1:
        return True, int(value)
    if isinstance(old, str):
        return True, str(value)
    d=value.denominator
    for p in (2,5):
        while d % p == 0:
            d //= p
    if d != 1:
        return False, None
    try:
        fv=float(value)
    except (OverflowError, ValueError):
        return False, None
    if not math.isfinite(fv) or Fraction(str(fv)) != value:
        return False, None
    return True, fv

def _equation_equal(a: Any, b: Any) -> bool:
    aq, bq = _fraction(a), _fraction(b)
    if aq is not None and bq is not None: return aq == bq
    return a == b


def analyze_expression_rules(root: Any, config: Any) -> AnalysisResult:
    result = AnalysisResult()
    rules = [x for x in (getattr(config, "constraint_rules", ()) or ()) if isinstance(x, dict) and x.get("kind") == "expression"]
    if not rules: return result
    arrays = {pointer(parts): (parts, arr) for parts, arr in constraint_object_arrays(root)}
    if getattr(config, "record_carrier_mode", False) and isinstance(root, list) and len(root) == 1 and isinstance(root[0], dict):
        arrays[""] = ([], root)
    for raw in rules:
        try: rule = compile_expression_rule(raw)
        except ExpressionIRException as exc:
            rid = str(raw.get("rule_id") or "expression")
            result.issues.append(Issue("expression_exact", "expression_rule_invalid", str(raw.get("array_path") or ""), str(exc), "error", False, {"rule_id": rid}))
            continue
        scope = rule["array_path"]; rid = rule["rule_id"]
        if scope not in arrays:
            result.issues.append(Issue("expression_exact", "expression_scope_missing", scope, "Expression scope does not resolve to an object array.", "error", False, {"rule_id": rid}))
            continue
        parts, arr = arrays[scope]
        result.relations.append({
            "relation_id": rid, "kind": "typed_expression_exact", "array_path": scope,
            "inputs": rule["fields"], "output": None, "confidence": 1.0, "support": len(arr),
            "constraint_source": "authoritative", "typed_expression_rule": rule,
        })
        for i, row in enumerate(arr):
            if not isinstance(row, dict): continue
            le = evaluate_expression(rule["lhs"], row); re = evaluate_expression(rule["rhs"], row)
            if le.status == "DOMAIN_ERROR" or re.status == "DOMAIN_ERROR":
                result.issues.append(Issue("expression_exact", "expression_domain_error", pointer(parts + [i]), "Exact expression is outside its declared operator domain.", "error", False,
                                           {"rule_id": rid, "left_status": le.status, "right_status": re.status, "left_reason": le.reason, "right_reason": re.reason}))
                continue
            satisfied = le.status == "VALUE" and re.status == "VALUE" and _equation_equal(le.value, re.value)
            if satisfied: continue
            candidates: list[Candidate] = []
            solve_rows = []
            for target in rule["solve_for"]:
                direct_value = None
                direct = False
                if rule["lhs"].get("op") == "field" and rule["lhs"].get("name") == target and _count_target(rule["rhs"], target) == 0:
                    ev = evaluate_expression(rule["rhs"], row)
                    if ev.status == "VALUE": direct, direct_value = True, ev.value
                elif rule["rhs"].get("op") == "field" and rule["rhs"].get("name") == target and _count_target(rule["lhs"], target) == 0:
                    ev = evaluate_expression(rule["lhs"], row)
                    if ev.status == "VALUE": direct, direct_value = True, ev.value
                if direct:
                    status, value, reason = "UNIQUE", direct_value, None
                else:
                    status, value, reason = solve_equation(rule["lhs"], rule["rhs"], target, row)
                solve_rows.append({"target": target, "status": status, "reason": reason, "value": str(value) if isinstance(value,Fraction) else value})
                if status != "UNIQUE" or value is None: continue
                old = row.get(target)
                representable, new_value = _native_exact_value(value, old)
                if not representable:
                    solve_rows[-1]["status"] = "OPEN_NONFINITE_JSON_NUMBER"
                    solve_rows[-1]["reason"] = "exact rational has no finite JSON-number representation"
                    continue
                trial = dict(row); trial[target] = new_value
                tl = evaluate_expression(rule["lhs"], trial); tr = evaluate_expression(rule["rhs"], trial)
                if tl.status != "VALUE" or tr.status != "VALUE" or not _equation_equal(tl.value, tr.value): continue
                p = pointer(parts + [i, target])
                read_paths=[pointer(parts + [i, f]) for f in rule["fields"] if f != target]
                meta = {
                    "expression_rule_id": rid, "target": target, "relation_kind": "typed_expression_exact",
                    "add_if_missing": target not in row, "inverse_status": "UNIQUE", "rule_sha256": rule["rule_sha256"],
                    "exact_json_projection": True, "read_paths": read_paths, "write_paths": [p],
                }
                cid = "expr_" + hashlib.sha1((p + repr(new_value) + rid).encode()).hexdigest()[:16]
                candidates.append(Candidate(cid, "expression_exact", "replace", p, old, new_value,
                                            "Exact typed expression uniquely identifies this field value.", 1.0, 1, (rid,), meta))
            # de-duplicate identical path/value inversions
            uniq = {(c.path, json.dumps(c.new_value, sort_keys=True, default=str)): c for c in candidates}
            candidates = [uniq[k] for k in sorted(uniq)]
            path = pointer(parts + [i])
            code = "expression_violation" if le.status == "VALUE" and re.status == "VALUE" else "expression_unknown"
            repairable = bool(candidates)
            result.issues.append(Issue("expression_exact", code, path,
                                       "Authoritative typed expression is violated." if code == "expression_violation" else "Authoritative typed expression cannot be evaluated from current material.",
                                       "warning", repairable,
                                       {"rule_id": rid, "fields": rule["fields"], "solve_attempts": solve_rows, "candidate_count": len(candidates), "relation_kind": "typed_expression_exact"}))
            result.candidates.extend(candidates)
    return result


def expression_ir_summary(config: Any) -> dict[str, Any]:
    compiled = []
    invalid = []
    for raw in (getattr(config, "constraint_rules", ()) or ()):
        if not isinstance(raw, dict) or raw.get("kind") != "expression": continue
        try: compiled.append(compile_expression_rule(raw))
        except ExpressionIRException as exc: invalid.append({"rule_id": raw.get("rule_id"), "error": str(exc)})
    return {
        "contract": CONTRACT, "rule_count": len(compiled), "invalid_rule_count": len(invalid),
        "rules": compiled, "invalid_rules": invalid,
        "operator_set": sorted({op for r in compiled for op in r.get("operators", [])}),
        "exact_arithmetic": True,
    }
