"""Phần dùng chung khi đọc log: đọc file an toàn từng dòng, kiểm tra đường dẫn, đọc JSON."""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

STORED_PREFIX_BYTES = 4096  # how much of an oversized line is kept as evidence


class ParseError(ValueError):
    """A raw line could not be parsed. ``reason`` is a short machine-readable code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


_ESCAPED_SURROGATE = re.compile(r"\\u[dD][89a-fA-F]")
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def load_json_line(line: str) -> object:
    """``json.loads`` for one log line: rejects NaN/Infinity and removes lone surrogates.

    JSON may contain escapes such as ``"\\ud800"`` (a lone UTF-16 surrogate, which
    Windows file names can hold). Python decodes it into a string that SQLite
    cannot store, so such characters are replaced by U+FFFD. The raw line is
    kept unchanged as evidence. Raises ``json.JSONDecodeError``/``RecursionError``
    like ``json.loads`` and ``ParseError`` for non-standard constants.
    """
    obj = json.loads(line, parse_constant=reject_json_constant)
    if _ESCAPED_SURROGATE.search(line):
        obj = _clean_surrogates(obj)
    return obj


def _clean_surrogates(value: object) -> object:
    if isinstance(value, str):
        return _LONE_SURROGATE.sub("\ufffd", value)
    if isinstance(value, dict):
        return {_clean_surrogates(k): _clean_surrogates(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean_surrogates(v) for v in value]
    return value


def reject_json_constant(name: str) -> None:
    """``json.loads(parse_constant=...)`` hook: NaN/Infinity are not valid JSON (RFC 8259)."""
    raise ParseError("malformed_json", f"non-standard JSON constant {name}")


class InputPathError(Exception):
    """The requested input file is missing or outside the allowed folders."""


@dataclass(frozen=True)
class LineRecord:
    line_no: int
    text: str
    too_long: bool = False
    end_offset: int = 0          # vị trí (byte) ngay sau dòng này trong file
    # line_no đếm từ vị trí bắt đầu đọc (start_offset), không phải từ đầu file
    complete: bool = True        # False: dòng cuối chưa có ký tự xuống dòng (có thể đang được ghi dở)


def iter_lines(path: Path, max_len: int, start_offset: int = 0) -> Iterator[LineRecord]:
    """Đọc file từng dòng một (generator), không nạp cả file vào RAM.

    Vì sao không dùng `for line in open(path)`: một dòng "độc" dài hàng trăm MB
    sẽ bị đọc trọn vào RAM. Ở đây mỗi lần chỉ đọc tối đa max_len + 2 byte;
    dòng dài hơn max_len được trả về với too_long=True (chỉ giữ 4096 byte đầu
    làm bằng chứng) và phần còn lại bị bỏ qua.
    start_offset > 0: bắt đầu đọc từ vị trí đó (chế độ watch chỉ đọc phần mới).
    """
    with open(path, "rb") as handle:                 # đọc dạng byte rồi tự giải mã UTF-8
        handle.seek(start_offset)
        line_no = 0
        while True:
            chunk = handle.readline(max_len + 2)      # đọc tối đa max_len + 2 byte của dòng hiện tại
            if not chunk:
                break                                 # hết file
            line_no += 1
            if line_no == 1 and start_offset == 0 and chunk.startswith(b"\xef\xbb\xbf"):
                chunk = chunk[3:]                     # bỏ BOM của file UTF-8 do Notepad tạo
            body = chunk.rstrip(b"\r\n")
            complete = chunk.endswith(b"\n")
            if len(body) > max_len:                   # dòng quá dài
                if not complete:
                    while True:  # đọc bỏ phần còn lại của dòng quá dài
                        rest = handle.readline(65536)
                        if not rest or rest.endswith(b"\n"):
                            complete = bool(rest)
                            break
                text = body[:STORED_PREFIX_BYTES].decode("utf-8", errors="replace")
                yield LineRecord(line_no, text, True, handle.tell(), complete)
                continue
            yield LineRecord(line_no, body.decode("utf-8", errors="replace"), False, handle.tell(), complete)


def resolve_input_path(path: str | Path, allowed_dirs: Iterable[Path]) -> Path:
    """Return the resolved path if it is a regular file inside an allowed folder.

    Symlinks and ``..`` segments are resolved before the containment check, so
    traversal out of the allowed folders is rejected.
    """
    try:
        resolved = Path(path).resolve(strict=False)
    except (OSError, ValueError, TypeError) as exc:
        raise InputPathError(f"invalid input path: {path!r}") from exc
    allowed = False
    for base in allowed_dirs:
        try:
            resolved.relative_to(Path(base).resolve(strict=False))
            allowed = True
            break
        except ValueError:
            continue
    if not allowed:
        raise InputPathError(f"input path is outside the allowed input folders: {resolved}")
    if not resolved.is_file():
        raise InputPathError(f"input file not found: {resolved}")
    return resolved
