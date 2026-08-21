from __future__ import annotations
from fractions import Fraction
from typing import Any
import hashlib,json
from .models import AnalysisResult,Issue,Candidate,pointer
from .analyzers import object_arrays


def constraint_object_arrays(root):
    """Authoritative DSL scopes are allowed on any non-empty object array.

    Discovery analyzers keep their >=3-row evidence floor; explicit constraints do not need
    empirical support because their authority comes from the supplied rule set.
    """
    out=[]
    def rec(v,parts):
        if isinstance(v,list) and v and all(isinstance(x,dict) for x in v): out.append((parts,v))
        if isinstance(v,dict):
            for k,x in v.items(): rec(x,parts+[k])
        elif isinstance(v,list):
            for i,x in enumerate(v): rec(x,parts+[i])
    rec(root,[])
    return out

def q(v:Any)->Fraction|None:
    if isinstance(v,bool) or v is None: return None
    if isinstance(v,int): return Fraction(v)
    if isinstance(v,float): return Fraction(str(v))
    if isinstance(v,str):
        try:return Fraction(v)
        except:return None
    return None

def native(fr:Fraction, old:Any=None):
    if fr.denominator==1:return int(fr)
    if isinstance(old,str):return str(fr)
    return float(fr)

def _solve(A:list[list[Fraction]],b:list[Fraction],n:int):
    if not A:return 'UNDERDETERMINED',None,0
    M=[row[:] + [rhs] for row,rhs in zip(A,b)]; m=len(M); rank=0; piv=[]
    for col in range(n):
        p=next((i for i in range(rank,m) if M[i][col]),None)
        if p is None: continue
        M[rank],M[p]=M[p],M[rank]; z=M[rank][col]; M[rank]=[x/z for x in M[rank]]
        for i in range(m):
            if i!=rank and M[i][col]:
                z=M[i][col]; M[i]=[a-z*c for a,c in zip(M[i],M[rank])]
        piv.append(col); rank+=1
    for row in M:
        if all(x==0 for x in row[:n]) and row[n]!=0:return 'INCONSISTENT',None,rank
    if rank<n:return 'UNDERDETERMINED',None,rank
    sol=[Fraction(0)]*n
    for i,col in enumerate(piv): sol[col]=M[i][n]
    return 'UNIQUE',sol,rank

def analyze_linear_rules(root,config):
    r=AnalysisResult(); rules=[x for x in getattr(config,'constraint_rules',()) if x.get('kind')=='linear']
    arrays={pointer(parts):(parts,arr) for parts,arr in constraint_object_arrays(root)}
    if getattr(config,'record_carrier_mode',False) and isinstance(root,list) and len(root)==1 and isinstance(root[0],dict): arrays['']=([],root)
    for scope in sorted(set(str(x.get('array_path','')) for x in rules)):
        scoped=[x for x in rules if str(x.get('array_path',''))==scope]
        if scope not in arrays:
            r.issues.append(Issue('linear_exact','constraint_scope_missing',scope,'Linear constraint scope does not resolve to a repeated object array.','error',False,{'array_path':scope})); continue
        parts,arr=arrays[scope]; fields=sorted(set().union(*(x.get('coefficients',{}).keys() for x in scoped)))
        relid='linear_'+hashlib.sha256(json.dumps(scoped,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:20]
        r.relations.append({'relation_id':relid,'kind':'linear_exact_system','array_path':scope,'inputs':fields,'output':None,'confidence':1.0,'support':len(arr),'rule_ids':[x.get('rule_id') for x in scoped]})
        for i,row in enumerate(arr):
            if not isinstance(row,dict): continue
            missing=[f for f in fields if f not in row or q(row.get(f)) is None]
            # If fields are missing, solve all missing variables jointly from exact equations.
            candidates=[]; status=None; rank=0
            if missing:
                A=[];B=[]
                for rule in scoped:
                    coeff={f:Fraction(str(v)) for f,v in rule['coefficients'].items()}; rhs=Fraction(str(rule.get('constant','0'))); ok=True
                    rr=rhs; ar=[]
                    for f in fields:
                        c=coeff.get(f,Fraction(0))
                        if f in missing: ar.append(c)
                        else:
                            v=q(row.get(f));
                            if v is None: ok=False; break
                            rr-=c*v
                    if ok:A.append([ar[missing.index(f)] if f in missing else Fraction(0) for f in missing]);B.append(rr)
                status,sol,rank=_solve(A,B,len(missing))
                if status=='UNIQUE' and sol is not None:
                    for f,v in zip(missing,sol):
                        path=pointer(parts+[i,f]); old=row.get(f); meta={'linear_system_id':relid,'rank':rank,'unknowns':missing,'relation_kind':'linear_exact_system','add_if_missing':f not in row}
                        candidates.append(Candidate('lin_'+hashlib.sha1((path+str(v)).encode()).hexdigest()[:16],'linear_exact','replace',path,old,native(v,old),'Exact multivariable linear system uniquely identifies this value.',1.0,1,(relid,),meta))
            else:
                # Determine whether exactly one observed field can be changed to satisfy all equations.
                for target in fields:
                    vals=[]; valid=True
                    for rule in scoped:
                        coeff={f:Fraction(str(v)) for f,v in rule['coefficients'].items()}; ct=coeff.get(target,Fraction(0))
                        if ct==0: continue
                        rhs=Fraction(str(rule.get('constant','0')))
                        for f,c in coeff.items():
                            if f==target: continue
                            v=q(row.get(f));
                            if v is None: valid=False; break
                            rhs-=c*v
                        if not valid: break
                        vals.append(rhs/ct)
                    if valid and vals and all(v==vals[0] for v in vals) and q(row.get(target))!=vals[0]:
                        path=pointer(parts+[i,target]); meta={'linear_system_id':relid,'target':target,'relation_kind':'linear_exact_system'}
                        candidates.append(Candidate('lin_'+hashlib.sha1((path+str(vals[0])).encode()).hexdigest()[:16],'linear_exact','replace',path,row.get(target),native(vals[0],row.get(target)),'Changing this field restores every authoritative linear equation.',1.0,1,(relid,),meta))
                # A one-field reconstruction is admissible only if it closes the entire
                # authoritative system.  Secondary patch cost must never choose a causal
                # direction when several fields could each satisfy the equations.
                globally_valid=[]
                for cnd in candidates:
                    trial=dict(row); trial[cnd.path.rsplit('/',1)[-1].replace('~1','/').replace('~0','~')]=cnd.new_value
                    ok_all=True
                    for rule in scoped:
                        lhs=Fraction(0)
                        for f,coef in rule['coefficients'].items():
                            vv=q(trial.get(f))
                            if vv is None: ok_all=False; break
                            lhs += Fraction(str(coef))*vv
                        if not ok_all or lhs!=Fraction(str(rule.get('constant','0'))): ok_all=False; break
                    if ok_all: globally_valid.append(cnd)
                candidates=globally_valid if len(globally_valid)==1 else []
                status='UNIQUE_CANDIDATE' if len(globally_valid)==1 else ('AMBIGUOUS_CANDIDATES' if len(globally_valid)>1 else 'INCONSISTENT')
            # emit only if current row violates or lacks variables
            violated=bool(missing)
            for rule in scoped:
                if any(q(row.get(f)) is None for f in rule['coefficients']): continue
                lhs=sum(Fraction(str(c))*q(row[f]) for f,c in rule['coefficients'].items())
                if lhs!=Fraction(str(rule.get('constant','0'))): violated=True
            if violated:
                repairable=bool(candidates)
                meta={'linear_system_id':relid,'solve_status':status,'candidate_count':len(candidates),'rank':rank,'fields':fields}
                r.issues.append(Issue('linear_exact','linear_system_violation',pointer(parts+[i]),'Record violates authoritative exact linear constraints.', 'warning',repairable,meta))
                r.candidates.extend(candidates)
    return r

def analyze_simple_rules(root,config):
    r=AnalysisResult(); rules=[x for x in getattr(config,'constraint_rules',()) if x.get('kind') in {'required','type','enum','const','minimum','exclusiveMinimum','maximum','exclusiveMaximum','multipleOf','minLength','maxLength','pattern','minItems','maxItems','uniqueItems','minProperties','maxProperties'}]
    arrays={pointer(parts):(parts,arr) for parts,arr in constraint_object_arrays(root)}
    if getattr(config,'record_carrier_mode',False) and isinstance(root,list) and len(root)==1 and isinstance(root[0],dict): arrays['']=([],root)
    for rule in rules:
        scope=str(rule.get('array_path','')); rid=str(rule.get('rule_id') or 'constraint'); field=rule.get('field')
        if scope not in arrays:
            r.issues.append(Issue('constraint_dsl','constraint_scope_missing',scope,'Constraint scope does not resolve to a repeated object array.','error',False,{'rule_id':rid})); continue
        parts,arr=arrays[scope]; kind=rule['kind']
        r.relations.append({'relation_id':rid,'kind':'constraint_dsl_'+kind,'array_path':scope,'inputs':[],'output':field,'confidence':1.0,'support':len(arr),'constraint_source':'authoritative'})
        for i,row in enumerate(arr):
            if not isinstance(row,dict):continue
            p=pointer(parts+[i,field]); present=field in row; old=row.get(field)
            if kind=='required' and not present:
                has='default' in rule; meta={'rule_id':rid,'add_if_missing':True}
                r.issues.append(Issue('constraint_dsl','required_missing',p,'DSL requires this field.','warning',has,meta))
                if has:r.candidates.append(Candidate('dsl_'+hashlib.sha1((p+repr(rule['default'])).encode()).hexdigest()[:16],'constraint_dsl','replace',p,None,rule['default'],'Insert authoritative DSL default.',1.0,1,(rid,),meta))
            elif kind=='const' and (not present or old!=rule.get('value')):
                nv=rule.get('value'); meta={'rule_id':rid,'add_if_missing':not present}
                r.issues.append(Issue('constraint_dsl','const_violation',p,'DSL const violated.','warning',True,meta)); r.candidates.append(Candidate('dsl_'+hashlib.sha1((p+repr(nv)).encode()).hexdigest()[:16],'constraint_dsl','replace',p,old,nv,'Restore DSL const.',1.0,1,(rid,),meta))
            elif kind=='enum' and present and old not in rule.get('values',[]):
                vals=rule.get('values',[]); matches=[x for x in vals if isinstance(x,str) and isinstance(old,str) and x.casefold()==old.casefold()]; meta={'rule_id':rid,'domain':vals}
                r.issues.append(Issue('constraint_dsl','enum_violation',p,'DSL enum violated.','warning',len(matches)==1,meta))
                if len(matches)==1:r.candidates.append(Candidate('dsl_'+hashlib.sha1((p+repr(matches[0])).encode()).hexdigest()[:16],'constraint_dsl','replace',p,old,matches[0],'Canonicalize DSL enum.',1.0,1,(rid,),meta))
            elif kind=='type' and present:
                t=rule.get('type'); ok={'string':isinstance(old,str),'integer':isinstance(old,int) and not isinstance(old,bool),'number':isinstance(old,(int,float)) and not isinstance(old,bool),'boolean':isinstance(old,bool),'object':isinstance(old,dict),'array':isinstance(old,list),'null':old is None}.get(t,True)
                if not ok:r.issues.append(Issue('constraint_dsl','type_violation',p,f'DSL type {t!r} violated.','warning',False,{'rule_id':rid,'expected_type':t}))
            elif kind in {'minimum','exclusiveMinimum','maximum','exclusiveMaximum','multipleOf'} and present:
                ov=q(old); bound=q(rule.get('value')); violated=False; repairable=False; nv=None
                if ov is None or bound is None or (kind=='multipleOf' and bound<=0):
                    r.issues.append(Issue('constraint_dsl','numeric_boundary_type_violation',p,'DSL numeric boundary requires finite numeric value and valid bound.','error',False,{'rule_id':rid,'boundary_kind':kind,'boundary_value':rule.get('value')})); continue
                if kind=='minimum': violated=ov<bound; nv=native(bound,old); repairable=violated
                elif kind=='maximum': violated=ov>bound; nv=native(bound,old); repairable=violated
                elif kind=='exclusiveMinimum': violated=ov<=bound
                elif kind=='exclusiveMaximum': violated=ov>=bound
                else:
                    violated=(ov/bound).denominator!=1
                    if violated:
                        z=ov/bound; lo=z.numerator//z.denominator; hi=lo+1; a=bound*lo; b=bound*hi; da=abs(ov-a); db=abs(ov-b)
                        if da!=db: nv=native(a if da<db else b,old); repairable=True
                if violated:
                    meta={'rule_id':rid,'boundary_kind':kind,'boundary_value':rule.get('value'),'projection_metric':'absolute_numeric_distance' if repairable else None}
                    r.issues.append(Issue('constraint_dsl',f'{kind}_violation',p,f'DSL {kind} boundary violated.','warning',repairable,meta))
                    if repairable:r.candidates.append(Candidate('dsl_'+hashlib.sha1((p+repr(nv)+kind).encode()).hexdigest()[:16],'constraint_dsl','replace',p,old,nv,f'Project to unique nearest DSL {kind} boundary.',1.0,1,(rid,),meta))
            elif kind in {'minLength','maxLength'} and present and isinstance(old,str):
                n=len(old); b=int(rule.get('value',0)); violated=n<b if kind=='minLength' else n>b
                if violated:r.issues.append(Issue('constraint_dsl',f'{kind}_violation',p,f'DSL {kind} boundary violated.','warning',False,{'rule_id':rid,'length':n,'boundary_value':b}))
            elif kind=='pattern' and present and isinstance(old,str):
                from .schema_bridge import _safe_regex
                ok,matched=_safe_regex(str(rule.get('value','')),old)
                if not ok:r.issues.append(Issue('constraint_dsl','pattern_unsupported',p,'DSL pattern invalid or outside bounded safe-regex subset.','error',False,{'rule_id':rid,'pattern':rule.get('value')}))
                elif not matched:r.issues.append(Issue('constraint_dsl','pattern_violation',p,'DSL pattern boundary violated.','warning',False,{'rule_id':rid,'pattern':rule.get('value')}))
            elif kind in {'minItems','maxItems'} and present and isinstance(old,list):
                n=len(old); b=int(rule.get('value',0)); violated=n<b if kind=='minItems' else n>b
                if violated:r.issues.append(Issue('constraint_dsl',f'{kind}_violation',p,f'DSL {kind} boundary violated.','warning',False,{'rule_id':rid,'count':n,'boundary_value':b}))
            elif kind=='uniqueItems' and present and isinstance(old,list) and rule.get('value') is True:
                enc=[json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False) for x in old]
                if len(set(enc))!=len(enc):r.issues.append(Issue('constraint_dsl','uniqueItems_violation',p,'DSL uniqueItems boundary violated.','warning',False,{'rule_id':rid,'count':len(old)}))
            elif kind in {'minProperties','maxProperties'} and present and isinstance(old,dict):
                n=len(old); b=int(rule.get('value',0)); violated=n<b if kind=='minProperties' else n>b
                if violated:r.issues.append(Issue('constraint_dsl',f'{kind}_violation',p,f'DSL {kind} boundary violated.','warning',False,{'rule_id':rid,'count':n,'boundary_value':b}))
    return r

def _combine_numeric_boundary_candidates(root,config,a):
    from .boundary import project_numeric_boundary
    numeric={'minimum','exclusiveMinimum','maximum','exclusiveMaximum','multipleOf'}
    groups={}
    for rule in getattr(config,'constraint_rules',()) or ():
        if rule.get('kind') not in numeric:continue
        groups.setdefault((str(rule.get('array_path','')),str(rule.get('field'))),[]).append(rule)
    if not groups:return a
    numeric_rule_ids={str(r.get('rule_id')) for rs in groups.values() for r in rs}
    a.candidates=[c for c in a.candidates if str((c.metadata or {}).get('rule_id')) not in numeric_rule_ids]
    arrays={pointer(parts):(parts,arr) for parts,arr in constraint_object_arrays(root)}
    if getattr(config,'record_carrier_mode',False) and isinstance(root,list) and len(root)==1 and isinstance(root[0],dict):arrays['']=([],root)
    for (scope,field),rules in sorted(groups.items()):
        if scope not in arrays:continue
        parts,arr=arrays[scope]; constraints={}; duplicate=False
        for rule in rules:
            k=rule['kind'];v=rule.get('value')
            if k in constraints and constraints[k]!=v:duplicate=True
            constraints[k]=v
        if duplicate:continue
        evidence=tuple(sorted(str(r.get('rule_id')) for r in rules))
        for i,row in enumerate(arr):
            if not isinstance(row,dict) or field not in row:continue
            old=row[field]; proj=project_numeric_boundary(old,constraints,integer_domain=False)
            if proj.get('status')!='UNIQUE':continue
            nv=native(proj['value'],old)
            if nv==old:continue
            pth=pointer(parts+[i,field]);meta={'rule_ids':list(evidence),'relation_kind':'constraint_dsl_numeric_boundary_intersection',
                'active_numeric_keywords':sorted(constraints),'combined_projection':True,'projection_metric':'absolute_numeric_distance','projection_distance':str(proj.get('distance'))}
            a.candidates.append(Candidate('dslb_'+hashlib.sha1((pth+repr(nv)+repr(evidence)).encode()).hexdigest()[:16],'constraint_dsl','replace',pth,old,nv,
                'Project to the unique nearest point satisfying the complete authoritative DSL numeric boundary intersection.',1.0,1,evidence,meta))
    return a

def analyze_constraints(root,config):
    a=analyze_simple_rules(root,config); a=_combine_numeric_boundary_candidates(root,config,a); b=analyze_linear_rules(root,config)
    from .expression_ir import analyze_expression_rules
    e=analyze_expression_rules(root,config)
    a.issues.extend(b.issues);a.candidates.extend(b.candidates);a.relations.extend(b.relations)
    a.issues.extend(e.issues);a.candidates.extend(e.candidates);a.relations.extend(e.relations)
    return a
