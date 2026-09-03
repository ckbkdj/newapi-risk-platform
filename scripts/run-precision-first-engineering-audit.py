from pathlib import Path

path = Path(__file__).with_name("apply-precision-first-engineering-audit.py")
source = path.read_text(encoding="utf-8")
source = source.replace('    """# 精度优先的内部工程审计\\n\\n"', '    "# 精度优先的内部工程审计\\n\\n"', 1)
exec(compile(source, str(path), "exec"), {"__name__": "__main__", "__file__": str(path)})
