from pathlib import Path

path = Path(__file__).resolve().parents[1] / "scripts/apply-request-size-followup.py"
text = path.read_text(encoding="utf-8")
old = '''ci = ROOT / ".github/workflows/ci.yml"\ntext = ci.read_text(encoding="utf-8")\nif text.count("assert values['AUDIT_CONTEXT_TARGET_TOKENS'] == '260000'") != 2:\n    raise SystemExit("expected two CI assertions for historical 260000 target")\ntext = text.replace("assert values['AUDIT_CONTEXT_TARGET_TOKENS'] == '260000'", "assert values['AUDIT_CONTEXT_TARGET_TOKENS'] == '0'")\nci.write_text(text, encoding="utf-8")\n'''
new = '''ci = ROOT / ".github/workflows/ci.yml"\ntext = ci.read_text(encoding="utf-8")\nold_assert = "assert values['AUDIT_CONTEXT_TARGET_TOKENS'] == '260000'"\nnew_assert = "assert values['AUDIT_CONTEXT_TARGET_TOKENS'] == '0'"\nif text.count(old_assert) == 2:\n    text = text.replace(old_assert, new_assert)\nelif text.count(new_assert) != 2:\n    raise SystemExit("unexpected CI audit context target assertions")\nci.write_text(text, encoding="utf-8")\n'''
if text.count(old) != 1:
    raise SystemExit("CI patch anchor not found")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
