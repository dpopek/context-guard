# Context-Guard: Context Hygiene, Outlines & Isolation Guards

- **Voluntary `Search -> Outline -> Target`:** Before reading an unfamiliar source file (`>150` lines), search with native grep/glob tools or run `cg-outline <path>` to get structural `L<start>-L<end>` spans, then call `read_file` / `Read` on targeted ranges (`<= 200` lines).
- **Silent Overlap Trimming (Read Ledger v2):** Overlapping `read_file` / `Read` line ranges are tracked by `SHA-256` and trimmed to unread lines under `read_confirm_policy` (`"strict"` default for verified tool outputs; `"bounded"` opt-in).
- **Automatic Machine-Artifact Unwrap:** Reading large raw `MCP output.txt` (`>= 16 KB`), opt-in integration JSON stdout (`>= 6 KB`), or `transcript*.jsonl` artifacts automatically unwraps and outlines the payload (`L<start>-L<end>`) so only relevant slices are read next.
- **Subagent Context Isolation:** Delegate heavy test failure logs (`>100` lines), multi-file exploration (`>4` files), or verbose MCP payloads (`>16 KB`) to an isolated research subagent and return a `<40`-line summary.
- **Zero Active Polling & Compaction Sensor:** Never poll background commands or subagents in a loop. On `CONTEXT-GUARD AUTO-COMPACT SENSOR` or `HARD STOP`, finish only the current atomic step and recommend `/compact` prominently.
- **Policy API v1 & Universal Config (`~/.config/context-guard/config.json`):** Configure verified `policy_packs`, `read_confirm_policy`, `optimizers`, and opt-in `integrations` per workspace rather than hardcoding private domain rules here.
