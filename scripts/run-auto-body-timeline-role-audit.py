from pathlib import Path

path = Path(__file__).with_name("apply-auto-body-timeline-role-audit.py")
source = path.read_text(encoding="utf-8")
source = source.replace('    """ALTER TABLE request_traces ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;\\n"', '    "ALTER TABLE request_traces ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;\\n"', 1)
source = source.replace('    """# 自动请求体、时间线与角色感知审计\\n\\n"', '    "# 自动请求体、时间线与角色感知审计\\n\\n"', 1)
code = compile(source, str(path), "exec")
exec(code, {"__name__": "__main__", "__file__": str(path)})
