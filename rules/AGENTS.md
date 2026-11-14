# Context-Guard: Context Hygiene, Outlines & Isolation Guards

- **Voluntary `Search -> Outline -> Target`:** Before reading an unfamiliar source file (`>150` lines), search with native grep/glob tools or run `cg-outline <path>` to get structural `L<start>-L<end>` spans, then call `read_file` / `Read` on targeted ranges (`<= 200` lines).
- **Silent Overlap Trimming:** Repeated or overlapping `read_file` / `Read` line ranges are tracked by `SHA-256` and silently trimmed to only unread lines (`range_trim`), never blocking edits or follow-up reads.
- **Automatic Machine-Artifact Unwrap:** Reading large raw `MCP output.txt` (`>= 16 KB`), `TWG stdout*.json` (`>= 6 KB`), or `transcript*.jsonl` artifacts automatically unwraps and outlines the payload (`L<start>-L<end>`) so only relevant slices are read next.
- **Subagent Context Isolation:** Delegate heavy test failure logs (`>100` lines), multi-file exploration (`>4` files), or verbose MCP payloads (`>16 KB`) to an isolated research subagent and return a `<40`-line summary.
- **Zero Active Polling & Compaction Sensor:** Never poll background commands or subagents in a loop. On `CONTEXT-GUARD AUTO-COMPACT SENSOR` or `HARD STOP`, finish only the current atomic step and recommend `/compact` prominently.
- **Workspace & Data Isolation (`~/.config/context-guard/config.json`):** Use `repo_map_path` local checkouts before `gitlab` MCP repo/file lookups, and query `allowed_bq_views_dataset` views instead of `restricted_bq_datasets`.
