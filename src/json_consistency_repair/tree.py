from __future__ import annotations
from typing import Any, Iterator
from .models import pointer


def walk(value: Any, parts: list[str|int] | None = None) -> Iterator[tuple[str, Any]]:
    parts = parts or []
    yield pointer(parts), value
    if isinstance(value, dict):
        for k,v in value.items():
            yield from walk(v, parts+[k])
    elif isinstance(value, list):
        for i,v in enumerate(value):
            yield from walk(v, parts+[i])


def decode_pointer(path: str) -> list[str]:
    if path == "": return []
    if not path.startswith("/"): raise ValueError(path)
    return [p.replace("~1", "/").replace("~0", "~") for p in path[1:].split("/")]


def get(root: Any, path: str) -> Any:
    cur=root
    for token in decode_pointer(path):
        if isinstance(cur, list): cur=cur[int(token)]
        else: cur=cur[token]
    return cur


def set_value(root: Any, path: str, value: Any) -> None:
    toks=decode_pointer(path)
    if not toks: raise ValueError("root replacement is handled separately")
    cur=root
    for token in toks[:-1]:
        cur = cur[int(token)] if isinstance(cur, list) else cur[token]
    last=toks[-1]
    if isinstance(cur,list): cur[int(last)] = value
    else: cur[last] = value


def delete_value(root: Any, path: str) -> None:
    toks=decode_pointer(path)
    cur=root
    for token in toks[:-1]:
        cur = cur[int(token)] if isinstance(cur,list) else cur[token]
    last=toks[-1]
    if isinstance(cur,list): del cur[int(last)]
    else: del cur[last]
