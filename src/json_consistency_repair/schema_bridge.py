from __future__ import annotations
from typing import Any
from fractions import Fraction
import hashlib,json,re,math
from .models import AnalysisResult,Issue,Candidate,pointer


def _json_equal(a:Any,b:Any)->bool:
    if isinstance(a,bool) or isinstance(b,bool): return type(a) is type(b) and a==b
    if a is None or b is None:return a is b
    if isinstance(a,(int,float)) and not isinstance(a,bool) and isinstance(b,(int,float)) and not isinstance(b,bool):
        try:return Fraction(str(a))==Fraction(str(b))
        except Exception:return a==b
    if type(a) is not type(b):return False
    if isinstance(a,list):return len(a)==len(b) and all(_json_equal(x,y) for x,y in zip(a,b))
    if isinstance(a,dict):return a.keys()==b.keys() and all(_json_equal(a[k],b[k]) for k in a)
    return a==b


def _type_ok(v,t):
    if isinstance(t,list): return any(_type_ok(v,x) for x in t)
    return {'object':lambda x:isinstance(x,dict),'array':lambda x:isinstance(x,list),'string':lambda x:isinstance(x,str),
            'integer':lambda x:isinstance(x,int) and not isinstance(x,bool) or (isinstance(x,float) and math.isfinite(x) and x.is_integer()),
            'number':lambda x:isinstance(x,(int,float)) and not isinstance(x,bool) and (not isinstance(x,float) or math.isfinite(x)),
            'boolean':lambda x:isinstance(x,bool),'null':lambda x:x is None}.get(t,lambda x:True)(v)


def _q(v:Any)->Fraction|None:
    if isinstance(v,bool) or v is None:return None
    if isinstance(v,int):return Fraction(v)
    if isinstance(v,float) and math.isfinite(v):return Fraction(str(v))
    return None


def _native(fr:Fraction,old:Any)->Any:
    if fr.denominator==1:return int(fr)
    return float(fr)


def _safe_regex(pattern:str,text:str)->tuple[bool,bool]:
    """Return (supported, matched). Reject a small dangerous-regex surface rather than risk unbounded backtracking."""
    if not isinstance(pattern,str) or len(pattern)>512 or len(text)>65536:return False,False
    # nested quantified groups are the classic catastrophic-backtracking form; do not execute them.
    if re.search(r'\([^)]*[+*][^)]*\)[+*{]',pattern):return False,False
    try:return True,re.search(pattern,text) is not None
    except re.error:return False,False


def _resolve_ref(ref:str,root:Any)->Any|None:
    if not ref.startswith('#/'):return None
    cur=root
    try:
        for tok in ref[2:].split('/'):
            tok=tok.replace('~1','/').replace('~0','~')
            cur=cur[int(tok)] if isinstance(cur,list) else cur[tok]
        return cur
    except Exception:return None


def schema_valid(v:Any,s:Any,root_schema:Any|None=None,depth:int=0,stack:tuple[str,...]=())->bool:
    if depth>64:return False
    if isinstance(s,bool):return s
    if not isinstance(s,dict):return True
    root_schema=s if root_schema is None else root_schema
    if isinstance(s.get('$ref'),str):
        ref=s['$ref']
        if ref in stack:return False
        target=_resolve_ref(ref,root_schema)
        if target is None:return False
        merged=target
        if isinstance(target,dict) and len(s)>1:
            merged=dict(target); merged.update({k:x for k,x in s.items() if k!='$ref'})
        return schema_valid(v,merged,root_schema,depth+1,stack+(ref,))
    t=s.get('type')
    if t is not None and not _type_ok(v,t):return False
    if 'const' in s and not _json_equal(v,s['const']):return False
    if isinstance(s.get('enum'),list) and not any(_json_equal(v,x) for x in s['enum']):return False
    q=_q(v)
    if q is not None:
        for key,op in [('minimum',lambda a,b:a>=b),('exclusiveMinimum',lambda a,b:a>b),('maximum',lambda a,b:a<=b),('exclusiveMaximum',lambda a,b:a<b)]:
            if key in s:
                b=_q(s[key])
                if b is None or not op(q,b):return False
        if 'multipleOf' in s:
            m=_q(s['multipleOf'])
            if m is None or m<=0 or (q/m).denominator!=1:return False
    if isinstance(v,str):
        if isinstance(s.get('minLength'),int) and len(v)<s['minLength']:return False
        if isinstance(s.get('maxLength'),int) and len(v)>s['maxLength']:return False
        if isinstance(s.get('pattern'),str):
            ok,matched=_safe_regex(s['pattern'],v)
            if not ok or not matched:return False
    if isinstance(v,list):
        if isinstance(s.get('minItems'),int) and len(v)<s['minItems']:return False
        if isinstance(s.get('maxItems'),int) and len(v)>s['maxItems']:return False
        if s.get('uniqueItems') is True:
            for i in range(len(v)):
                if any(_json_equal(v[i],v[j]) for j in range(i)):return False
        pref=s.get('prefixItems')
        if isinstance(pref,list):
            for i,sub in enumerate(pref[:len(v)]):
                if not schema_valid(v[i],sub,root_schema,depth+1,stack):return False
        items=s.get('items')
        start=len(pref) if isinstance(pref,list) else 0
        if isinstance(items,(dict,bool)):
            for x in v[start:]:
                if not schema_valid(x,items,root_schema,depth+1,stack):return False
        contains=s.get('contains')
        if isinstance(contains,(dict,bool)):
            n=sum(1 for x in v if schema_valid(x,contains,root_schema,depth+1,stack))
            mn=s.get('minContains',1); mx=s.get('maxContains')
            if not isinstance(mn,int):mn=1
            if n<mn or (isinstance(mx,int) and n>mx):return False
    if isinstance(v,dict):
        if isinstance(s.get('minProperties'),int) and len(v)<s['minProperties']:return False
        if isinstance(s.get('maxProperties'),int) and len(v)>s['maxProperties']:return False
        req=s.get('required')
        if isinstance(req,list) and any(k not in v for k in req if isinstance(k,str)):return False
        props=s.get('properties') if isinstance(s.get('properties'),dict) else {}
        pats=s.get('patternProperties') if isinstance(s.get('patternProperties'),dict) else {}
        evaluated=set()
        for k,sub in props.items():
            if k in v:
                evaluated.add(k)
                if not schema_valid(v[k],sub,root_schema,depth+1,stack):return False
        for pat,sub in pats.items():
            for k in v:
                ok,matched=_safe_regex(pat,k)
                if not ok:return False
                if matched:
                    evaluated.add(k)
                    if not schema_valid(v[k],sub,root_schema,depth+1,stack):return False
        add=s.get('additionalProperties',True)
        for k in v:
            if k in evaluated:continue
            if add is False:return False
            if isinstance(add,(dict,bool)) and not schema_valid(v[k],add,root_schema,depth+1,stack):return False
        pn=s.get('propertyNames')
        if isinstance(pn,(dict,bool)):
            for k in v:
                if not schema_valid(k,pn,root_schema,depth+1,stack):return False
        dep=s.get('dependentRequired')
        if isinstance(dep,dict):
            for k,needs in dep.items():
                if k in v and isinstance(needs,list) and any(x not in v for x in needs if isinstance(x,str)):return False
        deps=s.get('dependentSchemas')
        if isinstance(deps,dict):
            for k,sub in deps.items():
                if k in v and not schema_valid(v,sub,root_schema,depth+1,stack):return False
    allof=s.get('allOf')
    if isinstance(allof,list) and not all(schema_valid(v,x,root_schema,depth+1,stack) for x in allof):return False
    anyof=s.get('anyOf')
    if isinstance(anyof,list) and not any(schema_valid(v,x,root_schema,depth+1,stack) for x in anyof):return False
    oneof=s.get('oneOf')
    if isinstance(oneof,list) and sum(1 for x in oneof if schema_valid(v,x,root_schema,depth+1,stack))!=1:return False
    if 'not' in s and isinstance(s['not'],(dict,bool)) and schema_valid(v,s['not'],root_schema,depth+1,stack):return False
    if 'if' in s and isinstance(s['if'],(dict,bool)):
        branch='then' if schema_valid(v,s['if'],root_schema,depth+1,stack) else 'else'
        if branch in s and isinstance(s[branch],(dict,bool)) and not schema_valid(v,s[branch],root_schema,depth+1,stack):return False
    return True


def _candidate(cid_seed:str,p:str,old:Any,new:Any,reason:str,sid:str,keyword:str,meta:dict[str,Any]|None=None)->Candidate:
    m={'schema_id':sid,'schema_keyword':keyword,'boundary_projection':keyword in {'minimum','maximum','multipleOf'}}
    if meta:m.update(meta)
    return Candidate('sch_'+hashlib.sha1(cid_seed.encode()).hexdigest()[:16],'schema_bridge','replace',p,old,new,reason,1.0,1,(sid,),m)


def analyze_schema(root,config):
    schema=getattr(config,'json_schema',None); r=AnalysisResult()
    if not isinstance(schema,(dict,bool)) or schema in ({},None):return r
    sid='schema_'+hashlib.sha256(json.dumps(schema,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:20]
    r.relations.append({'relation_id':sid,'kind':'authoritative_json_schema','array_path':'','inputs':[],'output':'__schema__','confidence':1.0,'support':1,'schema_source':getattr(config,'schema_source','json_schema')})
    from .boundary import compile_boundary_registry
    for bc in compile_boundary_registry(schema,()).get('contracts',[]):
        r.relations.append({'relation_id':bc['boundary_id'],'kind':'authoritative_boundary_contract','array_path':bc.get('path_pattern',''),
                            'inputs':[],'output':'__boundary__','confidence':1.0,'support':1,'schema_source':getattr(config,'schema_source','json_schema'),
                            'boundary_contract':bc})
    def issue(code,p,msg,repairable=False,keyword=None,meta=None,severity='warning'):
        m={'schema_id':sid}
        if keyword:m['schema_keyword']=keyword
        if meta:m.update(meta)
        r.issues.append(Issue('schema_bridge',code,p,msg,severity,repairable,m))
    def walk(v,s,parts,depth=0,stack=()):
        if depth>64:
            issue('schema_depth_limit',pointer(parts),'Schema evaluation depth limit reached.',False,None,{},'error');return
        if isinstance(s,bool):
            if not s:issue('schema_false_violation',pointer(parts),'Boolean false schema rejects this value.',False,'boolean_schema')
            return
        if not isinstance(s,dict):return
        if isinstance(s.get('$ref'),str):
            ref=s['$ref']
            if ref in stack:issue('schema_ref_cycle',pointer(parts),'Cyclic local schema reference is not admissible.',False,'$ref',{'ref':ref},'error');return
            target=_resolve_ref(ref,schema)
            if target is None:issue('schema_ref_unresolved',pointer(parts),'Schema reference cannot be resolved locally.',False,'$ref',{'ref':ref},'error');return
            merged=target
            if isinstance(target,dict) and len(s)>1:
                merged=dict(target);merged.update({k:x for k,x in s.items() if k!='$ref'})
            walk(v,merged,parts,depth+1,stack+(ref,));return
        p=pointer(parts); t=s.get('type')
        if t is not None and not _type_ok(v,t):
            issue('schema_type_violation',p,f'Value violates authoritative schema type {t!r}.',False,'type',{'expected_type':t},'error'); return
        if 'const' in s and not _json_equal(v,s['const']):
            nv=s['const']; issue('schema_const_violation',p,'Value violates authoritative const.',True,'const')
            r.candidates.append(_candidate(p+repr(nv),p,v,nv,'Restore authoritative const.',sid,'const'))
        if isinstance(s.get('enum'),list) and not any(_json_equal(v,x) for x in s['enum']):
            vals=s['enum']; matches=[x for x in vals if isinstance(v,str) and isinstance(x,str) and x.casefold()==v.casefold()]
            rep=len(matches)==1;issue('schema_enum_violation',p,'Value lies outside authoritative enum.',rep,'enum',{'domain':vals})
            if rep:r.candidates.append(_candidate(p+repr(matches[0]),p,v,matches[0],'Canonicalize to unique authoritative enum value.',sid,'enum',{'domain':vals}))
        q=_q(v)
        if q is not None:
            from .boundary import project_numeric_boundary
            numeric_constraints={k:s[k] for k in ('minimum','exclusiveMinimum','maximum','exclusiveMaximum','multipleOf') if k in s}
            integer_domain=(s.get('type')=='integer')
            numeric_projection=project_numeric_boundary(v,numeric_constraints,integer_domain=integer_domain) if numeric_constraints else {'status':'VALID','value':q,'distance':0}
            projected_value=_native(numeric_projection['value'],v) if numeric_projection.get('status')=='UNIQUE' else None
            projection_repairable=bool(numeric_projection.get('status')=='UNIQUE' and schema_valid(projected_value,s,schema))
            # Inclusive finite boundaries and discrete lattices are projected only through the full boundary intersection.
            if 'minimum' in s:
                b=_q(s['minimum'])
                if b is None:issue('schema_invalid_boundary',p,'minimum is not a finite JSON number.',False,'minimum',severity='error')
                elif q<b:
                    nv=_native(b,v); meta={'boundary_value':s['minimum'],'projection_metric':'absolute_numeric_distance'}
                    issue('schema_minimum_violation',p,'Number lies below authoritative minimum.',projection_repairable,'minimum',{**meta,'combined_projection_status':numeric_projection.get('status')})
            if 'exclusiveMinimum' in s:
                b=_q(s['exclusiveMinimum'])
                if b is None:issue('schema_invalid_boundary',p,'exclusiveMinimum is not a finite JSON number.',False,'exclusiveMinimum',severity='error')
                elif q<=b:issue('schema_exclusive_minimum_violation',p,'Number does not satisfy authoritative exclusiveMinimum; no smallest admissible real correction exists.',False,'exclusiveMinimum',{'boundary_value':s['exclusiveMinimum']})
            if 'maximum' in s:
                b=_q(s['maximum'])
                if b is None:issue('schema_invalid_boundary',p,'maximum is not a finite JSON number.',False,'maximum',severity='error')
                elif q>b:
                    nv=_native(b,v);meta={'boundary_value':s['maximum'],'projection_metric':'absolute_numeric_distance'}
                    issue('schema_maximum_violation',p,'Number lies above authoritative maximum.',projection_repairable,'maximum',{**meta,'combined_projection_status':numeric_projection.get('status')})
            if 'exclusiveMaximum' in s:
                b=_q(s['exclusiveMaximum'])
                if b is None:issue('schema_invalid_boundary',p,'exclusiveMaximum is not a finite JSON number.',False,'exclusiveMaximum',severity='error')
                elif q>=b:issue('schema_exclusive_maximum_violation',p,'Number does not satisfy authoritative exclusiveMaximum; no largest admissible real correction exists.',False,'exclusiveMaximum',{'boundary_value':s['exclusiveMaximum']})
            if 'multipleOf' in s:
                m=_q(s['multipleOf'])
                if m is None or m<=0:issue('schema_invalid_multiple_of',p,'multipleOf must be a positive finite number.',False,'multipleOf',severity='error')
                elif (q/m).denominator!=1:
                    z=q/m; lo=(z.numerator//z.denominator); hi=lo+1; a=m*lo; b=m*hi; da=abs(q-a); db=abs(q-b)
                    unique=da!=db; nv=_native(a if da<db else b,v) if unique else None
                    meta={'multiple_of':s['multipleOf'],'nearest_tie':not unique,'projection_metric':'absolute_numeric_distance'}
                    repairable=projection_repairable;meta['combined_projection_status']=numeric_projection.get('status');issue('schema_multiple_of_violation',p,'Number is not an exact multiple of the authoritative step.',repairable,'multipleOf',meta)
            if numeric_constraints and numeric_projection.get('status')=='UNIQUE' and projection_repairable:
                meta={'active_numeric_keywords':sorted(numeric_constraints),'projection_metric':'absolute_numeric_distance',
                      'combined_projection':True,'projection_distance':str(numeric_projection.get('distance'))}
                r.candidates.append(_candidate(p+repr(projected_value)+'combined_numeric',p,v,projected_value,
                    'Project to the unique nearest point satisfying the complete authoritative numeric boundary intersection.',sid,'numeric_boundary_intersection',meta))
        if isinstance(v,str):
            if isinstance(s.get('minLength'),int) and len(v)<s['minLength']:issue('schema_min_length_violation',p,'String is shorter than authoritative minLength.',False,'minLength',{'length':len(v),'minimum':s['minLength']})
            if isinstance(s.get('maxLength'),int) and len(v)>s['maxLength']:issue('schema_max_length_violation',p,'String is longer than authoritative maxLength; destructive truncation is not inferred.',False,'maxLength',{'length':len(v),'maximum':s['maxLength']})
            if isinstance(s.get('pattern'),str):
                ok,matched=_safe_regex(s['pattern'],v)
                if not ok:issue('schema_pattern_unsupported',p,'Pattern is invalid or outside the bounded safe-regex subset.',False,'pattern',{'pattern':s['pattern']},'error')
                elif not matched:issue('schema_pattern_violation',p,'String does not match authoritative pattern.',False,'pattern',{'pattern':s['pattern']})
        if isinstance(v,dict):
            if isinstance(s.get('minProperties'),int) and len(v)<s['minProperties']:issue('schema_min_properties_violation',p,'Object has too few properties.',False,'minProperties',{'count':len(v),'minimum':s['minProperties']})
            if isinstance(s.get('maxProperties'),int) and len(v)>s['maxProperties']:issue('schema_max_properties_violation',p,'Object has too many properties; arbitrary deletion is not inferred.',False,'maxProperties',{'count':len(v),'maximum':s['maxProperties']})
            props=s.get('properties',{}) if isinstance(s.get('properties',{}),dict) else {}; req=s.get('required',[]) if isinstance(s.get('required',[]),list) else []
            for k in req:
                if not isinstance(k,str) or k in v:continue
                ps=props.get(k,{}) if isinstance(props.get(k,{}),dict) else {}; pp=pointer(parts+[k]); has='default' in ps;meta={'field':k,'add_if_missing':True}
                issue('schema_required_missing',pp,'Authoritative schema requires this property.',has,'required',meta)
                if has:r.candidates.append(_candidate(pp+repr(ps['default']),pp,None,ps['default'],'Insert authoritative schema default.',sid,'required',meta))
            evaluated=set()
            for k,sv in props.items():
                if k in v:evaluated.add(k);walk(v[k],sv,parts+[k],depth+1,stack)
            pats=s.get('patternProperties',{}) if isinstance(s.get('patternProperties'),dict) else {}
            for pat,sv in sorted(pats.items()):
                for k in v:
                    ok,matched=_safe_regex(pat,k)
                    if not ok:issue('schema_pattern_property_unsupported',pointer(parts+[k]),'patternProperties expression is invalid or outside bounded safe-regex subset.',False,'patternProperties',{'pattern':pat},'error');continue
                    if matched:evaluated.add(k);walk(v[k],sv,parts+[k],depth+1,stack)
            add=s.get('additionalProperties',True)
            for k in v:
                if k in evaluated:continue
                pp=pointer(parts+[k])
                if add is False:issue('schema_additional_property',pp,'Property forbidden by authoritative schema; removal is not automatic without explicit policy.',False,'additionalProperties')
                elif isinstance(add,(dict,bool)):walk(v[k],add,parts+[k],depth+1,stack)
            pn=s.get('propertyNames')
            if isinstance(pn,(dict,bool)):
                for k in v:
                    if not schema_valid(k,pn,schema):issue('schema_property_name_violation',pointer(parts+[k]),'Property name violates authoritative propertyNames schema.',False,'propertyNames',{'property_name':k})
            dep=s.get('dependentRequired')
            if isinstance(dep,dict):
                for trigger,needs in dep.items():
                    if trigger not in v or not isinstance(needs,list):continue
                    for k in needs:
                        if not isinstance(k,str) or k in v:continue
                        pp=pointer(parts+[k]);ps=props.get(k,{}) if isinstance(props.get(k,{}),dict) else {};has='default' in ps;meta={'trigger':trigger,'field':k,'add_if_missing':True}
                        issue('schema_dependent_required_missing',pp,'Property is required by authoritative dependentRequired.',has,'dependentRequired',meta)
                        if has:r.candidates.append(_candidate(pp+repr(ps['default'])+'dep',pp,None,ps['default'],'Insert authoritative default required by dependentRequired.',sid,'dependentRequired',meta))
            deps=s.get('dependentSchemas')
            if isinstance(deps,dict):
                for trigger,sub in deps.items():
                    if trigger in v:walk(v,sub,parts,depth+1,stack)
        elif isinstance(v,list):
            if isinstance(s.get('minItems'),int) and len(v)<s['minItems']:issue('schema_min_items_violation',p,'Array has fewer items than authoritative minItems.',False,'minItems',{'count':len(v),'minimum':s['minItems']})
            if isinstance(s.get('maxItems'),int) and len(v)>s['maxItems']:issue('schema_max_items_violation',p,'Array has more items than authoritative maxItems; arbitrary deletion is not inferred.',False,'maxItems',{'count':len(v),'maximum':s['maxItems']})
            if s.get('uniqueItems') is True:
                dup=sum(1 for i in range(len(v)) if any(_json_equal(v[i],v[j]) for j in range(i)))
                if dup:issue('schema_unique_items_violation',p,'Array violates authoritative uniqueItems; duplicate removal is not inferred automatically.',False,'uniqueItems',{'duplicate_occurrences':dup})
            pref=s.get('prefixItems')
            if isinstance(pref,list):
                for i,sub in enumerate(pref[:len(v)]):walk(v[i],sub,parts+[i],depth+1,stack)
            items=s.get('items');start=len(pref) if isinstance(pref,list) else 0
            if isinstance(items,(dict,bool)):
                for i in range(start,len(v)):walk(v[i],items,parts+[i],depth+1,stack)
            contains=s.get('contains')
            if isinstance(contains,(dict,bool)):
                n=sum(1 for x in v if schema_valid(x,contains,schema,depth+1,stack));mn=s.get('minContains',1);mx=s.get('maxContains')
                if not isinstance(mn,int):mn=1
                if n<mn:issue('schema_min_contains_violation',p,'Array contains too few items matching authoritative contains schema.',False,'minContains',{'matches':n,'minimum':mn})
                if isinstance(mx,int) and n>mx:issue('schema_max_contains_violation',p,'Array contains too many items matching authoritative contains schema.',False,'maxContains',{'matches':n,'maximum':mx})
        allof=s.get('allOf')
        if isinstance(allof,list):
            for sub in allof:walk(v,sub,parts,depth+1,stack)
        anyof=s.get('anyOf')
        if isinstance(anyof,list) and not any(schema_valid(v,x,schema,depth+1,stack) for x in anyof):issue('schema_anyof_violation',p,'No authoritative anyOf branch accepts the value; branch selection is ambiguous.',False,'anyOf',{'branch_count':len(anyof)})
        oneof=s.get('oneOf')
        if isinstance(oneof,list):
            n=sum(1 for x in oneof if schema_valid(v,x,schema,depth+1,stack))
            if n!=1:issue('schema_oneof_violation',p,'Authoritative oneOf requires exactly one matching branch.',False,'oneOf',{'matching_branches':n,'branch_count':len(oneof)})
        if 'not' in s and isinstance(s['not'],(dict,bool)) and schema_valid(v,s['not'],schema,depth+1,stack):issue('schema_not_violation',p,'Value matches an authoritative forbidden not-schema.',False,'not')
        if 'if' in s and isinstance(s['if'],(dict,bool)):
            branch='then' if schema_valid(v,s['if'],schema,depth+1,stack) else 'else'
            if branch in s and isinstance(s[branch],(dict,bool)):walk(v,s[branch],parts,depth+1,stack)
    walk(root,schema,[])
    # Stable de-dup can arise from allOf/dependentSchemas convergence.
    r.issues=list({x.signature():x for x in r.issues}.values())
    r.candidates=list({x.candidate_id:x for x in r.candidates}.values())
    return r
