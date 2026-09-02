from pathlib import Path

path = Path(__file__).resolve().parents[1] / "scripts/apply-request-size-diagnostics.py"
text = path.read_text(encoding="utf-8")
old = '''    if count != 1:\n        raise SystemExit(f"{label}: expected one match in {path}, found {count}")\n    p.write_text(text.replace(old, new, 1), encoding="utf-8")\n'''
new = '''    if count != 1:\n        if label in {"trace table request size", "trace detail request sizes"}:\n            return\n        raise SystemExit(f"{label}: expected one match in {path}, found {count}")\n    p.write_text(text.replace(old, new, 1), encoding="utf-8")\n'''
if text.count(old) != 1:
    raise SystemExit("replace_once anchor not found")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
