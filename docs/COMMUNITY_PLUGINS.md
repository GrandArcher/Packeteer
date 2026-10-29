# Community plugins

Plugins written and maintained outside this repository. The Packeteer maintainers do not audit, endorse, or support them; read the code before you run it. How to write one: [PLUGIN_AUTHORING.md](PLUGIN_AUTHORING.md).

To add a plugin, open a PR that adds one row to the table. Keep the rows in alphabetical order by name. A row needs:

1. **Name** and **Link**: an `https://` link to a public repository.
2. **Kind**: one of the kinds in [PLUGINS.md](PLUGINS.md#extension-points-pkgplugin), written as `prober`, `source`, `rib_source`, and so on.
3. **Delivery**: `exec`, `grpc`, or `compiled-in` (a fork or a patch that adds the package to `internal/plugins/all`).
4. **Affects routing**: `no` or `yes`. An `exec` or `grpc` plugin is a prober, source, or notifier and cannot announce, so it is always `no`. A compiled-in announcer, RIB source, leak source, RPKI or IRR source, detector, elector, federation, scorer, or policy is `yes`, and its README must say how it keeps the safety rules in [AGENTS.md](../AGENTS.md). The other kinds are `no`.
5. **License**: an SPDX identifier (for example `Apache-2.0`).

The repository you link to must also have:

- a license file, and a README with the config block, an example, and the Packeteer version it was tested against;
- tests that run without a real network or real prefixes (documentation ranges only);
- a maintainer who answers issues. A row whose repository is archived or unanswered for a year can be removed by PR.

The list is not a registry and Packeteer does not download plugins.

## Plugins

| Name | Kind | Delivery | Affects routing | License | Link |
|---|---|---|---|---|---|
