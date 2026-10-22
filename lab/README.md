# Test lab

Five real PHP containers on either side of the CVE-2026-109618 / CVE-2026-109619 fix, for validating the scanner against genuine PHP instead of mocks.

> **Some of these containers run an unpatched PHP.** Every port is bound to `127.0.0.1` in `docker-compose.yml`. Keep it that way, never publish them on a network, and run `docker compose down` when you're done.

```bash
docker compose up -d
python3 ../scanner.py --cli --authorized --deep --oracle \
    -t 127.0.0.1:18101 -t 127.0.0.1:18102 -t 127.0.0.1:18103 -t 127.0.0.1:18104 -t 127.0.0.1:18105 \
    --evidence evidence.md
docker compose down
```

| Port | Image | Config | Passive scan | With `--oracle` |
|---|---|---|---|---|
| 18101 | `php:8.5.11-apache` | default (version visible) | `VULNERABLE` (version) | `VULNERABLE` (oracle 3/3) |
| 18102 | `php:8.5.12-apache` | default (version visible) | `PATCHED` (version) | `PATCHED` (oracle 2/3) |
| 18103 | `php:8.5.11-apache` | `expose_php=Off` | `INDETERMINATE` | `VULNERABLE` (oracle 3/3) |
| 18104 | `php:8.5.11-apache` | `expose_php=Off`, `display_errors=Off` | `INDETERMINATE` | `INDETERMINATE` (no signal to read) |
| 18105 | `php:8.5.12-apache` | `expose_php=Off` | `INDETERMINATE` | `PATCHED` (oracle 2/3) |

The 18103 and 18105 rows are the point of the oracle: nothing in the headers or page identifies the PHP build, yet the behavioral check separates the unpatched build from the fixed one. 18104 shows the honest limit: with errors off there is nothing to read.

Output captured from this lab is in [`../examples/`](../examples/).
