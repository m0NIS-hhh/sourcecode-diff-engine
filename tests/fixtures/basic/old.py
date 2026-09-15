def parse_chunk_header(line: str) -> tuple[int, str]:
    size_part, _, ext = line.partition(';')
    size = int(size_part.strip(), 16)
    return size, ext.strip()
def render_index(names: list[str]) -> str:
    rows = []
    for name in names:
        rows.append(f'<li><a href="{name}">{name}</a></li>')
    return '<ul>' + ''.join(rows) + '</ul>'
def json_key_sql(key: str) -> str:
    alias = f'"{key}"'
    return f'SELECT payload ->> %s AS {alias} FROM events'
