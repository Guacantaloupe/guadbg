# GuaDbg 命令的键名表

**由 `sky-re/tools/gen_cmd_schema.py` 从 `engine/guadbg_core.cpp` 自动生成，不要手改。**

为什么要这张表：

两轮里同一个形状咬了两次——`search_str` 的参数键是 `s` 而我传了 `pattern`，
`list_bps` 的结果键是 `breakpoints` 而我读了 `bps`。两次都不是引擎的问题，
是**键名没有一处集中说明**。所以这张表从源码抽出，供调用者查，不用猜。

| 命令 | 参数键 | 结果键 |
|---|---|---|
| `ping` | — | `pong` |
| `get_state` | — | `state`, `paused_tid`, `reason`, `rip` |
| `pause` | — | `ok`, `note`, `error`, `threads` |
| `resume` | — | — |
| `step_into` | — | — |
| `step_over` | — | — |
| `step_out` | — | — |
| `run_to` | `addr` | `error`, `temp_bp` |
| `set_rip` | `addr` | `error`, `ok` |
| `get_regs` | — | `error`, `regs`, `tid` |
| `set_reg` | `name`, `value` | `error`, `ok` |
| `read_mem` | `addr`, `len` | `error`, `addr`, `len`, `hex` |
| `write_mem` | `hex`, `addr` | `error`, `ok`, `written` |
| `fill_mem` | `addr`, `len`, `val` | `error`, `ok` |
| `search_bytes` | `pattern`, `start`, `end` | `error`, `hits` |
| `search_str` | `s`, `pattern`, `start`, `end`, `unicode` | `error`, `hits`, `regions_scanned`, `regions_skipped`, `bytes_scanned`, `windows_scanned` |
| `mem_map` | — | `regions` |
| `disasm` | `addr`, `count` | `error`, `lines` |
| `windows` | — | `windows`, `count` |
| `list_threads` | — | `threads` |
| `get_ctx` | `tid` | `error`, `regs` |
| `set_thread_reg` | `name`, `tid`, `value` | `error`, `ok` |
| `suspend_thread` | `tid` | `error`, `ok` |
| `resume_thread` | `tid` | `error`, `ok` |
| `set_bp` | `cond`, `log`, `addr`, `once`, `silent` | `error`, `id`, `addr` |
| `set_hw_bp` | `mode`, `cond`, `addr`, `size` | `error`, `id` |
| `set_mem_bp` | `cond`, `addr`, `size` | `error`, `id` |
| `del_bp` | `id` | `error`, `ok` |
| `toggle_bp` | `id`, `enabled` | `error`, `ok` |
| `list_bps` | — | `breakpoints` |
| `list_modules` | — | `modules` |
| `exports` | `module` | `error`, `exports` |
| `list_imports` | — | `imports`, `count`, `captured`, `truncated` |
| `read_stack` | `count` | `error`, `stack` |
| `call_stack` | — | `error`, `frames`, `candidates` |
| `set_patch` | `hex`, `addr` | `error`, `id` |
| `list_patches` | — | `patches` |
| `restore_patch` | `id` | `error`, `ok` |
| `toggle_patch` | `id`, `enabled` | `error`, `ok` |
| `set_label` | — | — |
| `set_comment` | — | `error`, `ok` |
| `get_mark` | `addr` | `label`, `comment`, `bookmark` |
| `list_marks` | `kind` | `marks` |
| `resolve_name` | `name` | `error`, `addr` |
| `start_trace` | `cond`, `mode`, `max` | `error` |
| `stop_trace` | — | `ok`, `total` |
| `get_trace` | `from`, `count` | `total`, `entries` |
| `eval` | `expr` | `error`, `str`, `num` |
| `get_log` | `since` | `next`, `entries` |
| `clear_log` | — | `ok` |
| `terminate` | `code` | `error` |

共 51 个命令。
