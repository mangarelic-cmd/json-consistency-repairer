from __future__ import annotations
from decimal import Decimal, InvalidOperation
from typing import Any


def decimal_of(v: Any) -> Decimal | None:
    if isinstance(v,bool) or v is None: return None
    if isinstance(v,int): return Decimal(v)
    if isinstance(v,float): return Decimal(str(v))
    if isinstance(v,str):
        s=v.strip()
        if not s: return None
        try: return Decimal(s)
        except InvalidOperation: return None
    return None


def exact_equal(a: Any,b: Any) -> bool:
    da,db=decimal_of(a),decimal_of(b)
    if da is not None and db is not None: return da==db
    return a==b


def canonical_number(d: Decimal) -> int|float|str:
    if d == d.to_integral_value(): return int(d)
    f=float(d)
    if Decimal(str(f))==d: return f
    return format(d, 'f')


def canonical_number_like(d: Decimal, examples: list[Any] | None = None) -> int|float|str:
    """Render an exact Decimal while preserving the dominant JSON representation when safe."""
    examples=[x for x in (examples or []) if x is not None and not isinstance(x,bool)]
    if examples:
        kinds={"str":0,"int":0,"float":0}
        for x in examples:
            if isinstance(x,str) and decimal_of(x) is not None: kinds["str"]+=1
            elif isinstance(x,int): kinds["int"]+=1
            elif isinstance(x,float): kinds["float"]+=1
        kind=max(kinds,key=kinds.get)
        if kinds[kind]>0:
            if kind=="str": return format(d,'f')
            if kind=="int" and d==d.to_integral_value(): return int(d)
            if kind=="float": return float(d)
    return canonical_number(d)
