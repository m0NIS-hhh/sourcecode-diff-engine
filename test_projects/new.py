from html import escape
from urllib.parse import quote
import re
def parse_chunk_header(line: str) -> tuple[int, str]:
    size_part, _, ext = line.partition(';')
    if '\r' in ext or '\n' in ext:
        raise ValueError('invalid chunk extension')
    size = int(size_part.strip(), 16)
    return size, ext.strip()
def render_index(names: list[str]) -> str:
    rows = []
    for name in names:
        rows.append(f'<li><a href="{quote(name)}">{escape(name)}</a></li>')
    return '<ul>' + ''.join(rows) + '</ul>'
_ALIAS = re.compile(r'^[A-Za-z0-9_]+$')
def json_key_sql(key: str) -> str:
    safe = key if _ALIAS.match(key) else 'key_alias'
    alias = f'"{safe}"'
    return f'SELECT payload ->> %s AS {alias} FROM events'
