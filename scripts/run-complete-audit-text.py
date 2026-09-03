from pathlib import Path

script_path = Path(__file__).with_name("apply-complete-audit-text.py")
source = script_path.read_text(encoding="utf-8")
start_marker = "ci_path = ROOT / \".github/workflows/ci.yml\"\n"
end_marker = "ci_path.write_text(ci, encoding=\"utf-8\")\n"
start = source.find(start_marker)
end = source.find(end_marker, start)
if start < 0 or end < 0:
    raise SystemExit("CI mutation block was not found")
end += len(end_marker)
source = source[:start] + source[end:]
exec(compile(source, str(script_path), "exec"), {"__name__": "__main__", "__file__": str(script_path)})
