from pathlib import Path

path = Path(__file__).resolve().parents[1] / "internal/platform/adaptive_rules.go"
text = path.read_text(encoding="utf-8")
old = '''\t\tON CONFLICT(code) DO UPDATE SET pattern=EXCLUDED.pattern,description=EXCLUDED.description,
\t\t\tcategory=EXCLUDED.category,action=EXCLUDED.action,enabled=TRUE,updated_at=now()
'''
new = '''\t\tON CONFLICT(code) DO UPDATE SET pattern=EXCLUDED.pattern,description=EXCLUDED.description,
\t\t\tcategory=EXCLUDED.category,
\t\t\taction=CASE
\t\t\t\tWHEN cyber_rules.action='block' OR EXCLUDED.action='block' THEN 'block'
\t\t\t\tELSE EXCLUDED.action
\t\t\tEND,
\t\t\tenabled=TRUE,updated_at=now()
'''
if text.count(old) != 1:
    raise SystemExit(f"adaptive promotion SQL anchor count={text.count(old)}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
print("adaptive promotion action is now monotonic")
