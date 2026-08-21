from __future__ import annotations
from fractions import Fraction
import json,re,hashlib
from typing import Any

class ConstraintDSLError(ValueError): pass

def _num(s:str)->str:
    try: return str(Fraction(s.strip()))
    except Exception as e: raise ConstraintDSLError(f'invalid rational {s!r}') from e

def _linear_side(text:str)->tuple[dict[str,Fraction],Fraction]:
    # affine expressions: field, 2*field, -3/2*field, numeric constants
    text=text.replace('-','+-')
    coeff={}; const=Fraction(0)
    for raw in text.split('+'):
        t=raw.strip()
        if not t: continue
        if '*' in t:
            a,b=t.split('*',1); a=a.strip(); b=b.strip()
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',b): raise ConstraintDSLError(f'invalid field {b!r}')
            c=Fraction(a or '1'); coeff[b]=coeff.get(b,Fraction(0))+c
        elif re.fullmatch(r'-?[A-Za-z_][A-Za-z0-9_.-]*',t):
            sign=-1 if t.startswith('-') else 1; f=t[1:] if t.startswith('-') else t
            coeff[f]=coeff.get(f,Fraction(0))+sign
        else: const += Fraction(t)
    return coeff,const

def parse_dsl(text:str)->tuple[dict[str,Any],...]:
    scope=''; out=[]
    for lineno,line in enumerate(text.splitlines(),1):
        line=line.strip()
        if not line or line.startswith('#'): continue
        if line.startswith('scope '):
            scope=line[6:].strip();
            if scope!='' and not scope.startswith('/'): raise ConstraintDSLError(f'line {lineno}: scope must be JSON Pointer')
            continue
        m=re.match(r'require\s+([A-Za-z_][\w.-]*)(?:\s+default\s+(.+))?$',line)
        if m:
            rule={'kind':'required','array_path':scope,'field':m.group(1)}
            if m.group(2): rule['default']=json.loads(m.group(2))
            out.append(rule); continue
        m=re.match(r'type\s+([A-Za-z_][\w.-]*)\s+(string|integer|number|boolean|object|array|null)$',line)
        if m: out.append({'kind':'type','array_path':scope,'field':m.group(1),'type':m.group(2)}); continue
        m=re.match(r'enum\s+([A-Za-z_][\w.-]*)\s+(.+)$',line)
        if m:
            vals=json.loads(m.group(2));
            if not isinstance(vals,list) or not vals: raise ConstraintDSLError(f'line {lineno}: enum must be non-empty JSON array')
            out.append({'kind':'enum','array_path':scope,'field':m.group(1),'values':vals}); continue
        m=re.match(r'const\s+([A-Za-z_][\w.-]*)\s+(.+)$',line)
        if m: out.append({'kind':'const','array_path':scope,'field':m.group(1),'value':json.loads(m.group(2))}); continue
        m=re.match(r'(minimum|exclusiveMinimum|maximum|exclusiveMaximum|multipleOf)\s+([A-Za-z_][\w.-]*)\s+(.+)$',line)
        if m:
            try: val=json.loads(m.group(3))
            except Exception as e: raise ConstraintDSLError(f'line {lineno}: numeric boundary must be JSON number') from e
            if isinstance(val,bool) or not isinstance(val,(int,float)): raise ConstraintDSLError(f'line {lineno}: numeric boundary must be JSON number')
            if m.group(1)=='multipleOf' and val<=0: raise ConstraintDSLError(f'line {lineno}: multipleOf must be positive')
            out.append({'kind':m.group(1),'array_path':scope,'field':m.group(2),'value':val}); continue
        m=re.match(r'(minLength|maxLength|minItems|maxItems|minProperties|maxProperties)\s+([A-Za-z_][\w.-]*)\s+(\d+)$',line)
        if m: out.append({'kind':m.group(1),'array_path':scope,'field':m.group(2),'value':int(m.group(3))}); continue
        m=re.match(r'uniqueItems\s+([A-Za-z_][\w.-]*)\s+(true|false)$',line,re.I)
        if m: out.append({'kind':'uniqueItems','array_path':scope,'field':m.group(1),'value':m.group(2).lower()=='true'}); continue
        m=re.match(r'pattern\s+([A-Za-z_][\w.-]*)\s+(.+)$',line)
        if m:
            try: pat=json.loads(m.group(2))
            except Exception as e: raise ConstraintDSLError(f'line {lineno}: pattern must be a JSON string') from e
            if not isinstance(pat,str): raise ConstraintDSLError(f'line {lineno}: pattern must be a JSON string')
            out.append({'kind':'pattern','array_path':scope,'field':m.group(1),'value':pat}); continue
        m=re.match(r'expr(?:\s+([A-Za-z_][\w.-]*))?\s*:\s*(.+?)\s*=\s*(.+)$',line)
        if m:
            from .expression_ir import parse_expression, ExpressionIRException
            try:
                lhs=parse_expression(m.group(2)); rhs=parse_expression(m.group(3))
            except ExpressionIRException as e:
                raise ConstraintDSLError(f'line {lineno}: {e}') from e
            rule={'kind':'expression','array_path':scope,'lhs':lhs,'rhs':rhs}
            if m.group(1): rule['name']=m.group(1)
            out.append(rule); continue
        m=re.match(r'linear(?:\s+([A-Za-z_][\w.-]*))?\s*:\s*(.+?)\s*=\s*(.+)$',line)
        if m:
            left,lc=_linear_side(m.group(2)); right,rc=_linear_side(m.group(3)); fields=set(left)|set(right)
            co={f:left.get(f,Fraction(0))-right.get(f,Fraction(0)) for f in fields}; co={f:c for f,c in co.items() if c}
            rhs=rc-lc
            if not co: raise ConstraintDSLError(f'line {lineno}: linear rule has no variable')
            rule={'kind':'linear','array_path':scope,'coefficients':{f:str(c) for f,c in sorted(co.items())},'constant':str(rhs)}
            if m.group(1): rule['name']=m.group(1)
            out.append(rule); continue
        raise ConstraintDSLError(f'line {lineno}: unsupported constraint syntax: {line}')
    for r in out:
        raw=json.dumps(r,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode(); r['rule_id']='dsl_'+hashlib.sha256(raw).hexdigest()[:20]
    return tuple(out)
