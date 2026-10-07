Responses of the pinned Fleet version (`FLEET_IMAGE` in `deploy/compose/versions.env`), recorded from the development
stack and trimmed to the fields the adapter reads:

- `get_config.json`: the configuration of a freshly set-up Fleet;
- `get_hosts.json`: the host list of the two test VMs;
- `get_host.json`: the host detail of paddock-u2404 with three of its packages, one of them with a matched CVE. The
  policy results were added in the shape Fleet returns them (`response` pass, fail, or empty before the host answered),
  because the recording predates Paddock's policies.
