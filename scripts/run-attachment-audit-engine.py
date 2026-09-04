from pathlib import Path

script_path = Path(__file__).with_name("apply-attachment-audit-engine.py")
source = script_path.read_text(encoding="utf-8")
exec(compile(source, str(script_path), "exec"), {"__name__": "__main__", "__file__": str(script_path)})

engine_path = script_path.resolve().parents[1] / "internal/platform/attachment_audit.go"
text = engine_path.read_text(encoding="utf-8")
old = '''\tdefer e.releaseAttachmentSlot()\n\n\tvar material attachmentMaterial\n'''
new = '''\tslotHeld := true\n\tdefer func() {\n\t\tif slotHeld {\n\t\t\te.releaseAttachmentSlot()\n\t\t}\n\t}()\n\n\tvar material attachmentMaterial\n'''
if old not in text and new not in text:
    raise SystemExit("attachment slot anchor not found")
text = text.replace(old, new, 1)
old = '''\tif material.Kind == attachmentKindArchive {\n\t\tchildren, expandErr := expandArchiveAttachment(\n'''
new = '''\tif material.Kind == attachmentKindArchive {\n\t\t// Do not hold a global model/fetch slot while recursively auditing archive\n\t\t// children. Otherwise enough concurrent archives could wait on slots held\n\t\t// by their own parents.\n\t\te.releaseAttachmentSlot()\n\t\tslotHeld = false\n\t\tchildren, expandErr := expandArchiveAttachment(\n'''
if old not in text and new not in text:
    raise SystemExit("archive slot release anchor not found")
text = text.replace(old, new, 1)
engine_path.write_text(text, encoding="utf-8")
