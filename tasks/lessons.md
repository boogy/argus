# Lessons

Mistake patterns encountered while executing
`/Users/bogdan/.claude/plans/how-can-we-better-elegant-engelbart.md`, encoded
as rules. Append a short entry (what happened, the rule) after each
correction; keep entries terse.

- **Never undo an edit with a git command.** `git checkout <file>`, `git
  restore <file>`, `git stash`, and `git reset --hard` act on the index, not
  the specific edit — they silently take unrelated uncommitted work with
  them. Undo an edit the same way it was made (reverse the `Edit`, or `cp`
  from a backup). Commit real work before introducing a temporary/
  experimental change into the same file; if committing isn't possible, back
  the file up outside the repo first.

- **A red commit poisons the resume signal.** Every task must reach a green
  `make verify` before it is committed. A task that cannot get there is
  reported back unfinished, never committed broken — the next session trusts
  `git log` as ground truth.

- **Neutralize, don't delete, when disabling code temporarily.** `if false
  && cond {` beats deleting the block: deleting orphans imports, breaks the
  build, and invites a destructive "just reset it" shortcut.

- **A mutation that fails nothing is a finding, not a formality.** Twice in T4
  the neutralized code broke no test, and neither time was the test at fault:
  once the guard was redundant (an earlier filter already enforced it), once
  the line was dead (every writer already created its parent chain). Ask
  *which* before writing a new test — the answer is often "delete the line".

- **Prove the escape, not the prefix.** `PathBuf::starts_with` is lexical, so
  `into/../x` "starts with" `into`. A traversal test has to assert on
  components (no `ParentDir`) or on canonicalized paths, or it passes against
  the very input it was written to catch.

- **`develop` was never verified on the current toolchain** — the edition-2024
  adoption commit (`8c8b3fd`) did not re-run `cargo fmt`, and a newer clippy
  added the `collapsible_if` lint (let-chains), which the existing code
  tripped in 7 places. A green `make verify` gate is worthless if the
  baseline was never green; verify the baseline before trusting it as a
  per-task gate.

- **Never pipe a mutation run through `head`.** A closed pipe kills the
  harness with SIGPIPE, so its `restore()` never runs and the working tree is
  left holding whichever mutation was applied when the pipe closed — a state
  that looks exactly like ordinary uncommitted work. It got committed and
  pushed in T18e before `make verify` was read. Two rules follow: write the
  full output to a file and read *that*, and read the verify exit code before
  running `git commit`, never in the same `;`-joined line.

- **Restore a mutant with `shutil.copy` (or `cp`), never `copy2`.** `copy2`
  copies the *metadata*, so the restored file carries the pre-mutation mtime —
  older than the artifact cargo just built from the mutated source. Cargo then
  rebuilds nothing, and the next `make verify` runs the mutant against the
  correct tree. In T28 that showed up as the opencode plugin test failing on a
  file no diff could explain. The content check (`restored == backup`) passes
  and proves nothing about this. `touch` every restored file, or copy without
  metadata.

- **Never retry a failing commit with `git commit -C <ref>`.** After a 1Password
  signing failure in T30 I retried in a loop with `-C ORIG_HEAD`, which reuses
  that ref's *message and author*: the attempt that finally got a signature
  landed the T30 diff under an unrelated older commit's subject and someone
  else's name. `--amend --reset-author -F -` repaired it, but the retry has to
  be the same `-F -` heredoc that failed, never a message borrowed from a ref
  whose contents were never checked.
