# Field report

No operator has reported Packeteer on a production edge yet; reports are collected in #54. `packeteer report --share` writes a short summary of your observe-mode install that is safe to paste into a field-report or bug issue. It reads the running controller, replaces what could identify your network, shows you the result, and writes a file only when you say yes. It sends nothing anywhere.

## What it holds

- Version, mode, and the number of providers.
- Whether iBGP sessions, add-path, and BMP are in use, and the prober and target source types.
- The setup checklist as ids and levels, such as `warn: bgp-down`. A provider's name is dropped from its id.
- The number of events, warnings, and critical events among the newest 1000 (warnings and critical events stand in for error counts), and a count per catalog event kind ([EVENTS.md](EVENTS.md)).
- The totals of the `value` report for the last 30 days, per basis (`announced`, `estimate`): improvements, measured improvements, steered hours, and the loss and latency avoided. It is empty without `storage`.

It holds no provider, router, or exchange name, no event text, no credential, and no community. Packeteer does not know your router's vendor or software version, so the issue form asks for it.

## Redaction

The whole text goes through one pass that replaces every IPv4 and IPv6 address and prefix, AS number, and host name:

| Value | Placeholder |
|---|---|
| IPv4 address | one of 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 |
| IPv6 address | 2001:db8::N |
| AS number (`AS64500`, `asn=64500`) | 64496 to 64511, then 65536 to 65551 |
| Host name | `router-N.example` |

A prefix keeps its length and gets a placeholder address. The same value always gets the same placeholder inside one report, and the same input gives the same text. A report with more distinct values than a pool holds (762 IPv4 addresses, 32 AS numbers) reuses placeholders; that never shows a real value. File names ending in `yaml`, `json`, `txt`, `log`, and similar extensions are left as they are.

## Run it

In the container, which reads `PACKETEER_CONFIG` and its `http.listen` to find the controller:

```
docker exec -it packeteer packeteer report --share
```

If `http.listen` is on a non-loopback address, give `-url https://...`. It prints the preview, then `Write packeteer-field-report.txt? [y/N]`. Anything but `y` or `yes` writes nothing. An existing file is never overwritten; give another name with `-out`.

| Flag | Meaning |
|---|---|
| `--share` | Required. |
| `-config FILE` | Config path, default `/etc/packeteer/config.yaml` (env `PACKETEER_CONFIG`). Its `http.listen` is where the controller is. |
| `-url URL` | Base URL of the controller instead. `https`, or `http` to a loopback address. |
| `-out FILE` | File to write, default `packeteer-field-report.txt`. |

The controller asks for sign-in by default. With the single basic-auth account (`PACKETEER_HTTP_USER` and `PACKETEER_HTTP_PASSWORD`, [ENV.md](ENV.md)) the container already has the variables. Otherwise set `PACKETEER_API_TOKEN` to an unscoped [API token](auth.md#api-tokens) of any role. The credentials go only to a loopback address or over https.

In the dashboard, Settings has a Field report panel: Preview shows the same text, and Download appears only after the preview is on the page. The API is `GET /api/report/share` ([API.md](API.md)).

## Share it

Open a [field report](../.github/ISSUE_TEMPLATE/field-report.yml) or a [bug](../.github/ISSUE_TEMPLATE/bug.yml) issue and paste the text. Read it once more first: the redaction is pattern based, so an address in an unusual form or a name that is not a host name could remain. Do not paste real prefixes, AS numbers, host names, or credentials anywhere else in the issue.

## Rollback

The command and the panel only read. Nothing is announced, no config key exists, and no file is written without a yes. Delete the file when you are done.
