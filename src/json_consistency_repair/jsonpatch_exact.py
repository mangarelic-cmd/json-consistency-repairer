from __future__ import annotations
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from .tree import decode_pointer, get
from .models import digest

MISSING = object()


def _parent(root: Any, path: str):
    toks = decode_pointer(path)
    if not toks:
        raise ValueError('root operation not supported by patch primitive')
    cur = root
    for token in toks[:-1]:
        cur = cur[int(token)] if isinstance(cur, list) else cur[token]
    return cur, toks[-1]


def _exists(root: Any, path: str) -> bool:
    try:
        get(root, path); return True
    except (KeyError, IndexError, TypeError, ValueError):
        return False


def _remove(root: Any, path: str, *, expected=MISSING):
    parent, last = _parent(root, path)
    if isinstance(parent, list):
        idx = int(last)
        if idx < 0 or idx >= len(parent):
            raise IndexError(path)
        old = parent[idx]
        if expected is not MISSING and old != expected:
            raise ValueError('remove precondition failed')
        del parent[idx]
        return deepcopy(old)
    if not isinstance(parent, dict) or last not in parent:
        raise KeyError(path)
    old = parent[last]
    if expected is not MISSING and old != expected:
        raise ValueError('remove precondition failed')
    del parent[last]
    return deepcopy(old)


def _add(root: Any, path: str, value: Any, *, require_absent: bool = False):
    parent, last = _parent(root, path)
    if isinstance(parent, list):
        if last == '-':
            parent.append(deepcopy(value)); return
        idx = int(last)
        if idx < 0 or idx > len(parent):
            raise IndexError(path)
        if require_absent and idx < len(parent):
            raise ValueError('add destination already occupied')
        parent.insert(idx, deepcopy(value)); return
    if not isinstance(parent, dict):
        raise TypeError('add parent must be object or array')
    if require_absent and last in parent:
        raise ValueError('add destination already occupied')
    parent[last] = deepcopy(value)


def _replace(root: Any, path: str, old: Any, new: Any):
    parent, last = _parent(root, path)
    if isinstance(parent, list):
        idx = int(last)
        if parent[idx] != old:
            raise ValueError('replace precondition failed')
        parent[idx] = deepcopy(new); return
    if not isinstance(parent, dict) or last not in parent or parent[last] != old:
        raise ValueError('replace precondition failed')
    parent[last] = deepcopy(new)


def apply_patch(root: Any, patch: dict[str, Any]) -> tuple[bool, dict[str, Any] | None]:
    """Apply one exact JSON transformation and return an exact inverse patch.

    Supported operations: add, remove, replace, move, copy, test, plan.
    Preconditions are deliberately stricter than RFC 6902 where needed for repair safety.
    """
    op = str(patch.get('operation') or patch.get('op') or '')
    path = str(patch.get('path', ''))
    meta = patch.get('metadata') or {}
    try:
        if op == 'plan':
            steps = meta.get('steps') or patch.get('steps') or []
            if not isinstance(steps, list) or not steps:
                return False, None
            expected_digest = patch.get('old_value')
            if isinstance(expected_digest, str) and len(expected_digest) == 64 and digest(root) != expected_digest:
                return False, None
            inverses=[]
            for step in steps:
                if not isinstance(step, dict) or str(step.get('operation') or step.get('op') or '') == 'plan':
                    for inv in reversed(inverses):
                        apply_patch(root, inv)
                    return False, None
                ok, inv = apply_patch(root, step)
                if not ok or inv is None:
                    for rollback in reversed(inverses):
                        apply_patch(root, rollback)
                    return False, None
                inverses.append(inv)
            target_digest = patch.get('new_value')
            if isinstance(target_digest, str) and len(target_digest) == 64 and digest(root) != target_digest:
                for rollback in reversed(inverses):
                    apply_patch(root, rollback)
                return False, None
            inverse_steps=list(reversed(inverses))
            return True, {'operation':'plan','path':'','old_value':deepcopy(target_digest) if isinstance(target_digest,str) else digest(root),
                          'new_value':deepcopy(expected_digest) if isinstance(expected_digest,str) else None,
                          'metadata':{'steps':inverse_steps,'inverse_of':'plan'}}

        if op == 'test':
            expected = patch.get('new_value', patch.get('value'))
            if get(root, path) != expected:
                return False, None
            return True, {'operation':'test','path':path,'new_value':deepcopy(expected),'old_value':deepcopy(expected),'metadata':{'inverse_of_test':True}}

        if op == 'replace':
            old = patch.get('old_value', MISSING)
            new = patch.get('new_value', patch.get('value'))
            if not _exists(root,path) and meta.get('add_if_missing'):
                _add(root,path,new,require_absent=True)
                return True, {'operation':'remove','path':path,'old_value':deepcopy(new),'new_value':None,'metadata':{'inverse_of':'replace-add'}}
            if old is MISSING:
                old = deepcopy(get(root, path))
            _replace(root, path, old, new)
            return True, {'operation':'replace','path':path,'old_value':deepcopy(new),'new_value':deepcopy(old),'metadata':{'inverse_of':'replace'}}

        if op == 'add':
            new = patch.get('new_value', patch.get('value'))
            existed = _exists(root, path)
            prior = deepcopy(get(root, path)) if existed else MISSING
            inverse_path = path
            if path.endswith('/-'):
                parent_path = path[:-2]
                container = get(root, parent_path) if parent_path else root
                if not isinstance(container, list):
                    return False, None
                inverse_path = (parent_path + '/' if parent_path else '/') + str(len(container))
            require_absent = bool(meta.get('require_absent', True))
            _add(root, path, new, require_absent=require_absent)
            if existed:
                return True, {'operation':'replace','path':path,'old_value':deepcopy(new),'new_value':prior,'metadata':{'inverse_of':'add-overwrite'}}
            return True, {'operation':'remove','path':inverse_path,'old_value':deepcopy(new),'new_value':None,'metadata':{'inverse_of':'add'}}

        if op == 'remove':
            expected = patch.get('old_value', MISSING)
            old = _remove(root, path, expected=expected)
            return True, {'operation':'add','path':path,'old_value':None,'new_value':old,'metadata':{'inverse_of':'remove','require_absent':True}}

        if op in {'move','copy'}:
            src = str(meta.get('from_path') or patch.get('from_path') or patch.get('from') or '')
            if not src:
                return False, None
            if op == 'move' and (path == src or path.startswith(src.rstrip('/') + '/')):
                return False, None
            value = deepcopy(get(root, src))
            if path and _exists(root, path):
                return False, None
            if op == 'move':
                removed = _remove(root, src, expected=patch.get('old_value', MISSING))
                try:
                    _add(root, path, removed, require_absent=True)
                except Exception:
                    _add(root, src, removed, require_absent=True)
                    raise
                return True, {'operation':'move','path':src,'old_value':deepcopy(value),'new_value':deepcopy(value),'metadata':{'from_path':path,'inverse_of':'move'}}
            _add(root, path, value, require_absent=True)
            return True, {'operation':'remove','path':path,'old_value':deepcopy(value),'new_value':None,'metadata':{'inverse_of':'copy'}}

        return False, None
    except (KeyError, IndexError, TypeError, ValueError):
        return False, None


def candidate_patch(candidate) -> dict[str, Any]:
    return {
        'operation': candidate.operation,
        'path': candidate.path,
        'old_value': deepcopy(candidate.old_value),
        'new_value': deepcopy(candidate.new_value),
        'metadata': deepcopy(candidate.metadata or {}),
    }


def apply_candidate(root: Any, candidate) -> bool:
    ok, _ = apply_patch(root, candidate_patch(candidate))
    return ok


def replay_with_inverses(root: Any, patches: list[dict[str, Any]]):
    current = deepcopy(root); inverses=[]
    for p in patches:
        ok, inv = apply_patch(current, p)
        if not ok or inv is None:
            return False, current, []
        inverses.append(inv)
    return True, current, list(reversed(inverses))
