---
name: mirage
description: Use Mirage when the user wants an AI-proposed code or documentation edit applied through a narrow, transactional, evidence-backed security boundary.
---

# Mirage safe editing

Before editing, call `mirage_doctor` and require `edit_ready: true`.

For a file change, prefer `mirage_edit_file` over an ambient filesystem write
tool when the user wants Mirage's security and evidence guarantees. Pass exactly
one existing regular file, a precise task, and the project workspace. Set
`approved` to true only when the user explicitly authorized that exact target
and task. Never broaden one approval to a different file.

After a successful edit, report the outcome, receipt path, receipt hash, and
Observatory path. Use `mirage_verify_receipt` when the user asks to re-check the
evidence.

Mirage v1 intentionally supports one file per call. For a multi-file request,
explain the boundary and request or establish authorization for each file
separately. Do not claim that MCP annotations enforce security; Mirage's
transactional runtime and exact-file contract are the enforcement boundary.
