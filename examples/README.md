# Example output

Captured from the local test lab in [`../lab/`](../lab/): real `php:8.5.11-apache` (unpatched) and `php:8.5.12-apache` (fixed) containers on `127.0.0.1`, scanned with the GUI and the CLI. Nothing here was captured from a third-party site.

| File | What it shows |
|---|---|
| [`lab-passive-output.txt`](lab-passive-output.txt) | Passive scan (`--deep`): the two hosts that disclose a version are graded; the three that hide it are `INDETERMINATE` |
| [`lab-oracle-output.txt`](lab-oracle-output.txt) | The same hosts with `--oracle`: the hidden-version hosts are now `VULNERABLE` / `PATCHED`; the errors-off host stays `INDETERMINATE` |
| [`lab-evidence.md`](lab-evidence.md) | The proof-of-finding report (`--evidence`): the exact request, the trimmed response, and a `curl` to replay it |
| [`lab-results.csv`](lab-results.csv) | The CSV export, including the `oracle_result` and `multipart_surface` columns |
| [`gui-results.png`](gui-results.png) | The GUI after scanning the lab |
| [`gui-detail-hidden-version.png`](gui-detail-hidden-version.png) | A row expanded: a host with no version disclosed, settled by the oracle |

The request in `lab-evidence.md` is the whole probe: one small multipart POST with an invalid session id. It reads how PHP reports the problem. It does not trigger the memory-corruption bug and writes nothing to the target.
