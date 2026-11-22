---
name: mirage
description: Use Mirage for transactional, evidence-backed edits to one explicitly authorized existing file.
---

Call `mirage_doctor` before the first edit and require `edit_ready: true`.
Prefer `mirage_edit_file` when the user requests Mirage protection. Set
`approved: true` only after the user authorizes that exact file and task. Never
reuse approval for another target. Report the receipt and Observatory paths
after success. Use `mirage_verify_receipt` to re-check evidence.

Mirage v1 intentionally edits one file per call. MCP annotations are user
interface hints; Mirage's transactional runtime is the enforcement boundary.
