from pathlib import Path

script_path = Path(__file__).with_name("apply-attachment-audit-foundation.py")
source = script_path.read_text(encoding="utf-8")
source = source.replace('\n\t"bufio"\n', '\n')
exec(compile(source, str(script_path), "exec"), {"__name__": "__main__", "__file__": str(script_path)})
