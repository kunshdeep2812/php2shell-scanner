# Example output

Captured from the local test lab in [`../lab/`](../lab/): real `php:8.5.11-apache` (unpatched) and `php:8.5.12-apache` (fixed) containers on `127.0.0.1`, scanned with the GUI and the CLI. Nothing here was captured from a third-party site.

| File | What it shows |
|---|---|
| [`lab-passive-output.txt`](lab-passive-output.txt) | Passive scan (`--deep`): the two hosts that disclose a version are graded; the three that hide it are `INDETERMINATE` |
| [`lab-oracle-output.txt`](lab-oracle-output.txt) | The same hosts with `--oracle`: the hidden-version hosts are now `VULNERABLE` / `PATCHED`; the errors-off host stays `INDETERMINATE` |
| [`lab-evidence.md`](lab-evidence.md) | The proof-of-finding report (`--evidence`): the exact request, the trimmed response, and a `curl` to replay it |
| [`lab-results.csv`](lab-results.csv) | The CSV export, including the `oracle_result` and `multipart_surface` columns |
| [`gui-1-empty.png`](gui-1-empty.png) | The GUI on first load, before anything is scanned |
| [`gui-2-form-filled.png`](gui-2-form-filled.png) | The form filled in: the five lab targets, scope, deep probes and active oracle enabled |
| [`gui-3-results.png`](gui-3-results.png) | Results after scanning the lab — also shown at the top of the main [`README`](../README.md) |
| [`gui-4-detail.png`](gui-4-detail.png) | A row expanded: `127.0.0.1:18103` discloses no PHP version at all, settled `VULNERABLE` by the active oracle |

The request in `lab-evidence.md` is the whole probe: one small multipart POST with an invalid session id. It reads how PHP reports the problem. It does not trigger the memory-corruption bug and writes nothing to the target.
