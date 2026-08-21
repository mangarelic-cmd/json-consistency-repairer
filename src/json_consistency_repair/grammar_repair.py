from __future__ import annotations
from dataclasses import dataclass
from typing import Any
import json, re

from .io import loads_strict
from .security import SecurityLimits

@dataclass(frozen=True)
class GrammarCandidate:
    operation:str
    position:int
    text:str
    cost:int=1


def _strip_js_comments(text:str) -> str | None:
    """Remove JS-style comments only outside quoted strings.

    This is a lexical adapter, not a JavaScript parser. Unterminated block comments
    are refused. Newlines from line comments are preserved so token separation is not
    silently changed.
    """
    out=[]; i=0; n=len(text); quote=None; esc=False; changed=False
    while i<n:
        ch=text[i]
        if quote is not None:
            out.append(ch)
            if esc: esc=False
            elif ch=='\\': esc=True
            elif ch==quote: quote=None
            i+=1; continue
        if ch in ('"', "'"):
            quote=ch; out.append(ch); i+=1; continue
        if ch=='/' and i+1<n and text[i+1]=='/':
            changed=True; i+=2
            while i<n and text[i] not in '\r\n': i+=1
            continue
        if ch=='/' and i+1<n and text[i+1]=='*':
            changed=True; end=text.find('*/',i+2)
            if end<0: return None
            # Preserve one blank when comment removal could concatenate tokens.
            before=out[-1] if out else ''
            after=text[end+2] if end+2<n else ''
            if before and after and (before.isalnum() or before in "\"'") and (after.isalnum() or after in "\"'"):
                out.append(' ')
            i=end+2; continue
        out.append(ch); i+=1
    return ''.join(out) if changed else None


def _quote_identifier_keys(text:str) -> str | None:
    """Quote bare identifier object keys, but never touch string contents."""
    out=[]; i=0; n=len(text); quote=None; esc=False; changed=False
    while i<n:
        ch=text[i]
        if quote is not None:
            out.append(ch)
            if esc: esc=False
            elif ch=='\\': esc=True
            elif ch==quote: quote=None
            i+=1; continue
        if ch in ('"', "'"):
            quote=ch; out.append(ch); i+=1; continue
        out.append(ch); i+=1
        if ch not in '{,': continue
        # copy whitespace after object delimiter
        while i<n and text[i].isspace(): out.append(text[i]); i+=1
        if i>=n or not (text[i].isalpha() or text[i]=='_'): continue
        j=i+1
        while j<n and (text[j].isalnum() or text[j] in '_-$'): j+=1
        k=j
        while k<n and text[k].isspace(): k+=1
        if k<n and text[k]==':':
            key=text[i:j]
            out.append(json.dumps(key,ensure_ascii=False))
            out.extend(text[j:k]); out.append(':')
            i=k+1; changed=True
    return ''.join(out) if changed else None


def _normalize_single_quoted_strings(text:str) -> str | None:
    """Convert closed single-quoted string tokens to JSON double-quoted strings.

    The adapter is deliberately lexical: it does not translate Python values or
    expressions. Unknown backslash escapes are left to strict JSON validation.
    """
    out=[]; i=0; n=len(text); changed=False
    while i<n:
        ch=text[i]
        if ch=='"':
            # Copy an existing JSON string verbatim.
            start=i; i+=1; esc=False
            while i<n:
                c=text[i]
                if esc: esc=False
                elif c=='\\': esc=True
                elif c=='"': i+=1; break
                i+=1
            out.append(text[start:i]); continue
        if ch!="'":
            out.append(ch); i+=1; continue
        i+=1; buf=[]; closed=False
        while i<n:
            c=text[i]
            if c=="'": closed=True; i+=1; break
            if c=='\\' and i+1<n:
                nxt=text[i+1]
                if nxt=="'": buf.append("'"); i+=2; continue
                # Preserve JSON-valid escapes; strict parsing validates them later.
                buf.append('\\'); buf.append(nxt); i+=2; continue
            if c=='"': buf.append('\\"')
            else: buf.append(c)
            i+=1
        if not closed: return None
        out.append('"'+''.join(buf)+'"'); changed=True
    return ''.join(out) if changed else None


def _dialect_candidates(text:str):
    rows=[]; seen=set()
    for op,fn in (
        ('strip_js_comments',_strip_js_comments),
        ('quote_unquoted_identifier_keys',_quote_identifier_keys),
        ('normalize_single_quoted_strings',_normalize_single_quoted_strings),
    ):
        try: candidate=fn(text)
        except Exception: candidate=None
        if candidate is not None and candidate!=text and candidate not in seen:
            seen.add(candidate); rows.append(GrammarCandidate(op,0,candidate,1))
    return rows


def _candidates(text:str, error:json.JSONDecodeError, max_candidates:int=128):
    pos=max(0,min(len(text),int(error.pos)))
    out=[]; seen=set()
    def add(op,p,s,cost=1):
        if s==text or s in seen or len(out)>=max_candidates: return
        seen.add(s); out.append(GrammarCandidate(op,p,s,cost))

    # Deterministic dirty-JSON adapters. They are considered only because the
    # strict parser already rejected the input; each result must still pass the
    # same strict decoder and converge canonically with every other minimum route.
    for c in _dialect_candidates(text):
        add(c.operation,c.position,c.text,c.cost)

    # Remove trailing comma and one unexpected delimiter around the parser failure.
    for m in re.finditer(r',\s*([}\]])',text):
        add('remove_trailing_comma',m.start(),text[:m.start()]+text[m.start()+1:])
    for p in range(max(0,pos-2),min(len(text),pos+3)):
        if text[p] in ',:]}{[':
            add('remove_unexpected_delimiter',p,text[:p]+text[p+1:])

    # Insert the only common JSON structural delimiters near the exact parser failure.
    for p in range(max(0,pos-1),min(len(text),pos+2)+1):
        for token,name in [(',', 'insert_comma'),(':','insert_colon'),('}','insert_object_close'),(']','insert_array_close')]:
            add(name,p,text[:p]+token+text[p:])

    # Truncated containers at EOF: only bounded closures, max two symbols.
    if pos>=len(text)-1:
        for suffix in ('}',']','}}',']}',']]', '}]'):
            add('close_truncated_container',len(text),text+suffix,len(suffix))

    # A single unterminated JSON string has one lexical delimiter missing.  Only
    # close it at the end of the current scalar, immediately before already
    # present trailing container delimiters (or at EOF).  We never rewrite quote
    # style or infer string content.
    if str(getattr(error,"msg","")).lower().startswith("unterminated string"):
        end=len(text)
        while end>0 and text[end-1].isspace(): end-=1
        insert=end
        while insert>0 and text[insert-1] in '}]': insert-=1
        add('close_unterminated_string',insert,text[:insert]+'"'+text[insert:])
    return out


def minimal_grammar_repair(text:str, limits:SecurityLimits|None=None, *, max_edit_distance:int=1, max_candidates:int=128):
    """Enumerate a bounded minimal JSON grammar frontier.

    PASS041 composes legal one-step grammar moves up to ``max_edit_distance``.
    This is a genuine bounded search, not a permissive JSON5 parser. PASS041
    adds three deterministic lexical adapters (comments, identifier keys, and
    single-quoted string tokens), but duplicate keys remain a hard ambiguity. A
    repair is accepted only when every minimum-cost successful route converges
    to one canonical JSON value.
    """
    lim=limits or SecurityLimits()
    try:
        return loads_strict(text,lim),[]
    except json.JSONDecodeError:
        pass
    except Exception:
        return None,[]

    # Dijkstra/BFS over the tiny edit algebra.  Costs are positive integers and
    # the default frontier is only two edits deep.
    frontier=[(0,text,tuple())]
    best_seen={text:0}
    valid=[]; expanded=0
    # ``max_candidates`` bounds one local parser frontier; a two-edit composed
    # search needs a slightly larger but still hard finite state budget or the
    # first layer can consume the entire allowance before any second move is
    # evaluated.
    state_budget=max(128,int(max_candidates)*8)
    while frontier:
        frontier.sort(key=lambda x:(x[0],x[1]))
        cost,current,route=frontier.pop(0)
        if cost>max_edit_distance: continue
        try:
            v=loads_strict(current,lim)
            canonical=json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
            valid.append((canonical,cost,route,v,current))
            continue
        except json.JSONDecodeError as err:
            if cost>=max_edit_distance: continue
            candidates=_candidates(current,err,max_candidates=max_candidates)
        except Exception:
            # Duplicate-key and safety failures are not grammar frontiers.
            continue
        for c in candidates:
            new_cost=cost+int(c.cost)
            if new_cost>max_edit_distance: continue
            prev=best_seen.get(c.text)
            if prev is not None and prev<new_cost: continue
            best_seen[c.text]=new_cost
            step={"operation":c.operation,"position":c.position,"cost":int(c.cost)}
            frontier.append((new_cost,c.text,route+(step,)))
            expanded+=1
            if expanded>=state_budget:
                frontier=[]
                break
    if not valid: return None,[]
    min_cost=min(x[1] for x in valid)
    valid=[x for x in valid if x[1]==min_cost]
    groups={}
    for canonical,cost,route,v,current in valid:
        groups.setdefault(canonical,[]).append((cost,route,v,current))
    if len(groups)!=1:
        return None,[]
    rows=next(iter(groups.values()))
    # All minimum-cost syntactic routes converge to exactly the same object.
    cost,route,v,current=sorted(rows,key=lambda x:(len(x[1]),json.dumps(x[1],sort_keys=True),len(x[3]),x[3]))[0]
    route_evidence=[]
    seen_routes=set()
    for rcost,rroute,_,_ in rows:
        key=json.dumps(rroute,sort_keys=True,separators=(',',':'))
        if key in seen_routes: continue
        seen_routes.add(key); route_evidence.append(list(rroute))
    return v,[{'operation':'bounded_minimal_composition' if len(route)>1 else route[0]['operation'],
              'position':route[0]['position'] if route else 0,'edit_distance':cost,'canonical_parse_unique':True,
              'route':list(route),'convergent_routes':route_evidence[:32]}]
