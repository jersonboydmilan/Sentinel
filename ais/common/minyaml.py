"""A strict, dependency free parser for the YAML subset used by AIS policies.

The prototype deliberately avoids third party dependencies: policy and profile
files are part of the security boundary, so the parser that reads them is kept
small, auditable and total. Supported subset:

* block mappings and block sequences, arbitrarily nested
* scalars: ``null``/``~``, booleans, ints, floats, quoted and bare strings
* inline flow lists ``[a, b, c]`` and flow maps ``{a: 1, b: 2}``
* ``#`` comments and blank lines
* multiple documents separated by ``---``

Anything outside the subset raises ``YamlSubsetError`` rather than guessing.
"""

from __future__ import annotations

from typing import Any

from .errors import AISError


class YamlSubsetError(AISError):
    """Raised when a document uses YAML features outside the supported subset."""


def _parse_scalar(token: str) -> Any:
    token = token.strip()
    if token == "" or token in {"null", "~", "Null", "NULL"}:
        return None
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        return token[1:-1]
    low = token.lower()
    if low in {"true", "yes", "on"}:
        return True
    if low in {"false", "no", "off"}:
        return False
    if token.startswith("[") and token.endswith("]"):
        return _parse_flow_list(token)
    if token.startswith("{") and token.endswith("}"):
        return _parse_flow_map(token)
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        pass
    return token


def _split_flow(body: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    quote = ""
    current = ""
    for ch in body:
        if quote:
            current += ch
            if ch == quote:
                quote = ""
            continue
        if ch in {'"', "'"}:
            quote = ch
            current += ch
        elif ch in "[{":
            depth += 1
            current += ch
        elif ch in "]}":
            depth -= 1
            current += ch
        elif ch == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += ch
    if current.strip():
        parts.append(current)
    return [p.strip() for p in parts if p.strip()]


def _parse_flow_list(token: str) -> list[Any]:
    return [_parse_scalar(part) for part in _split_flow(token[1:-1])]


def _parse_flow_map(token: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for part in _split_flow(token[1:-1]):
        if ":" not in part:
            raise YamlSubsetError(f"flow map entry without ':' -> {part!r}")
        key, _, value = part.partition(":")
        out[_parse_scalar(key)] = _parse_scalar(value)
    return out


class _Line:
    __slots__ = ("indent", "text", "number")

    def __init__(self, raw: str, number: int) -> None:
        stripped = raw.rstrip()
        self.indent = len(stripped) - len(stripped.lstrip(" "))
        self.text = stripped.strip()
        self.number = number


def _strip_comment(raw: str) -> str:
    out = ""
    quote = ""
    for ch in raw:
        if quote:
            out += ch
            if ch == quote:
                quote = ""
            continue
        if ch in {'"', "'"}:
            quote = ch
            out += ch
        elif ch == "#":
            break
        else:
            out += ch
    return out


def _tokenize(text: str) -> list[_Line]:
    lines: list[_Line] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if "\t" in raw.split("#")[0]:
            raise YamlSubsetError(f"tab indentation is not supported (line {number})")
        clean = _strip_comment(raw)
        if not clean.strip():
            continue
        lines.append(_Line(clean, number))
    return lines


def _parse_block(lines: list[_Line], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(lines):
        return None, index
    if lines[index].text.startswith("- "):
        return _parse_sequence(lines, index, indent)
    return _parse_mapping(lines, index, indent)


def _parse_sequence(lines: list[_Line], index: int, indent: int) -> tuple[list[Any], int]:
    items: list[Any] = []
    while index < len(lines):
        line = lines[index]
        if line.indent < indent or not (line.text == "-" or line.text.startswith("- ")):
            break
        if line.indent > indent:
            raise YamlSubsetError(f"unexpected indentation (line {line.number})")
        body = line.text[1:].strip()
        index += 1
        if not body:
            value, index = _parse_block(lines, index, indent + 1)
            items.append(value)
            continue
        if ":" in body and not body.startswith(("'", '"', "[", "{")):
            key, _, rest = body.partition(":")
            inline_indent = line.indent + 2
            synthetic = [_Line(" " * inline_indent + body, line.number)]
            nested_end = index
            while nested_end < len(lines) and lines[nested_end].indent >= inline_indent:
                synthetic.append(lines[nested_end])
                nested_end += 1
            value, _ = _parse_mapping(synthetic, 0, inline_indent)
            items.append(value)
            index = nested_end
            del key, rest
            continue
        items.append(_parse_scalar(body))
    return items, index


def _parse_mapping(lines: list[_Line], index: int, indent: int) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise YamlSubsetError(f"unexpected indentation (line {line.number})")
        if line.text.startswith("- "):
            break
        if ":" not in line.text:
            raise YamlSubsetError(f"expected 'key: value' (line {line.number}): {line.text!r}")
        key_token, _, value_token = line.text.partition(":")
        key = str(_parse_scalar(key_token))
        value_token = value_token.strip()
        index += 1
        if value_token:
            mapping[key] = _parse_scalar(value_token)
            continue
        if index < len(lines) and lines[index].indent > indent:
            value, index = _parse_block(lines, index, lines[index].indent)
            mapping[key] = value
        elif index < len(lines) and lines[index].indent == indent and lines[index].text.startswith("- "):
            value, index = _parse_sequence(lines, index, indent)
            mapping[key] = value
        else:
            mapping[key] = None
    return mapping, index


def loads(text: str) -> Any:
    """Parse a single document."""
    documents = load_all(text)
    if not documents:
        return None
    if len(documents) > 1:
        raise YamlSubsetError("multiple documents; use load_all()")
    return documents[0]


def load_all(text: str) -> list[Any]:
    """Parse every ``---`` separated document in ``text``."""
    chunks = [chunk for chunk in text.split("\n---")]
    documents: list[Any] = []
    for chunk in chunks:
        chunk = chunk.lstrip()
        if chunk.startswith("---"):
            chunk = chunk[3:]
        lines = _tokenize(chunk)
        if not lines:
            continue
        value, end = _parse_block(lines, 0, lines[0].indent)
        if end != len(lines):
            raise YamlSubsetError(f"trailing content at line {lines[end].number}")
        documents.append(value)
    return documents


def load_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return loads(handle.read())
