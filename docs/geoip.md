# GeoIP country database

Country rules need a MaxMind-format country database that you provide. Packeteer ships none. They are used by:

- a `rules` policy with `countries` (`geoip_db` in the policy config),
- FlowSpec mitigation rules with `source_countries` (`mitigation.geoip_db`).

Both read the file once at start, so restart after replacing it. The database only feeds policy input. It announces nothing.

## Where to get one

| Source | Format | Terms |
|---|---|---|
| MaxMind GeoLite Country | free account, license key; the download is gzip | The GeoLite EULA applies, and it requires you to delete a database within 30 days of a new release. MaxMind limits GeoLite accounts to 30 database downloads per day. Do not redistribute it. |
| DB-IP IP to Country Lite | `dbip-country-lite-YYYY-MM.mmdb.gz`, released monthly | Creative Commons Attribution 4.0: credit DB-IP.com for the data. |

Read the current terms on the vendor's site before you use a database. Packeteer's repository and image contain no database: the lab uses a tiny one that `lab/mkgeoip` writes for documentation prefixes.

## Mount it yourself

Download the file, unpack the `.mmdb`, and mount it read-only:

```
docker run ... -v "$PWD/GeoLite2-Country.mmdb:/etc/packeteer/GeoLite2-Country.mmdb:ro" ...
```

Point `geoip_db` at that path (an absolute path inside the container). Refresh it by replacing the file and restarting the container.

## Let Packeteer refresh it

The optional `geoip` block downloads the file for you and keeps it fresh. It is off unless `url` is set. See [CONFIG.md](CONFIG.md#geoip).

```yaml
geoip:
  path: /var/lib/packeteer/GeoLite2-Country.mmdb   # a writable volume
  url: https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz
  refresh: 168h
```

Use the permalink that your MaxMind account page shows for GeoLite Country; the `url` above is an example of its form. Set the account in the container's environment, never in the file:

```
docker run ... -v packeteer-data:/var/lib/packeteer \
  -e PACKETEER_GEOIP_USER=<account id> -e PACKETEER_GEOIP_KEY=<license key> ...
```

Then set `geoip_db: /var/lib/packeteer/GeoLite2-Country.mmdb` on the `rules` policy or `mitigation`.

What it does:

- On start it downloads the file when it is missing or older than `refresh`, before the policies read it. A failed first download is logged and the start goes on; a country rule then refuses the start if the file is not there.
- The file age is the server's `Last-Modified`, so once a release is older than `refresh` every start sends one conditional request. Keep `refresh` at 24h or more and do not restart in a loop.
- Every `refresh` it asks again with `If-Modified-Since`, so an unchanged file is not downloaded again.
- It accepts a raw `.mmdb`, a gzip of one, or a gzip tar archive holding one (the MaxMind form). A download is written next to the file, must parse as a country database with at least one network, and is then renamed over the old file. Any other result leaves the old file in place.
- A download over 128 MiB is refused. A redirect to plain http is refused (except to a loopback address). The account is sent only over https (or to a loopback address) and is never logged or returned by the API.
- A refreshed file is read at the next start. The download does not reload running policies.
- `PACKETEER_GEOIP_USER` and `PACKETEER_GEOIP_KEY` go together (HTTP basic authentication: for MaxMind, the account ID and the license key). A source that needs no account, such as a mirror you host, needs neither.

DB-IP names its file by month, so a fixed `url` does not fit it; download that one yourself and mount it.

## Checklist

The Overview checklist warns when a country rule's database file cannot be read, and when the download fails (it shows the last error). `-check` does not download.

Rollback: remove the `geoip` block and restart; the file stays where it is and `geoip_db` keeps reading it.
