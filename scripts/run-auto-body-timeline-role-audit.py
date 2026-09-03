from pathlib import Path

path = Path(__file__).with_name("apply-auto-body-timeline-role-audit.py")
source = path.read_text(encoding="utf-8")
source = source.replace('    """ALTER TABLE request_traces ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;\\n"', '    "ALTER TABLE request_traces ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;\\n"', 1)
source = source.replace('    """# 自动请求体、时间线与角色感知审计\\n\\n"', '    "# 自动请求体、时间线与角色感知审计\\n\\n"', 1)

# PR #13 already inserted detailed request-limit fields between the generic
# problem reason and the upstream reason. Remove the older exact-anchor patch
# from the staged script and apply the correlation fields against the current
# tree after the main integration has run.
label = '"web trace detail correlation fields"'
label_pos = source.index(label)
block_start = source.rfind("web = replace_once(", 0, label_pos)
block_end = source.index("\n)\n", label_pos) + len("\n)\n")
source = source[:block_start] + source[block_end:]

code = compile(source, str(path), "exec")
exec(code, {"__name__": "__main__", "__file__": str(path)})

web_path = path.parents[1] / "internal/platform/web/index.html"
web = web_path.read_text(encoding="utf-8")
anchor = "          ['建议请求体上限',item.metadata?.request_body_recommended_limit_bytes?byteText(item.metadata.request_body_recommended_limit_bytes):'-'], ['解决建议',item.metadata?.request_body_remediation||'-'], ['上游错误原因',item.metadata?.upstream_error_reason||'-'],\n"
addition = anchor + "          ['请求 ID 来源',item.metadata?.request_id_source||'-'], ['时间持续',item.metadata?.timeline_duration_ms!=null?`${number(item.metadata.timeline_duration_ms)} ms`:'-'], ['跟踪时间来源',item.metadata?.tracking_time_source||'gateway'], ['NewAPI→入库偏差',item.metadata?.tracking_clock_offset_ms!=null?`${number(item.metadata.tracking_clock_offset_ms)} ms`:'-'],\n"
if web.count(anchor) != 1:
    raise SystemExit(f"current Web correlation anchor count={web.count(anchor)}")
web_path.write_text(web.replace(anchor, addition, 1), encoding="utf-8")
