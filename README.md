# split-horizon-dns-helper

Helper to maintain rewrite rules for homelab split horizon DNS setup.

Reads certificates and/or router rules from [Traefik Proxy](https://traefik.io/traefik) and creates rewrite rules in [AdGuard Home](https://adguard.com/)

See [config.yml.template](config.yml.template) for configuration.

Run as one off or with a scheduler (cron, systemd).

## QNAP Traefik ACME DNS-01

The QNAP Traefik instance uses DNS-01 so the NAS does not need public HTTP or
HTTPS exposure. Traefik must be able to discover the authoritative zone with
SOA queries. AdGuard Home DNS rewrites can intercept those queries, so use the
`custom_filtering_rules` section for hostnames that need private A answers
while allowing other record types through to the upstream resolver:

```yaml
custom_filtering_rules:
  192.168.2.5:
    - hubmann.casa
  192.168.2.9:
    - backup.hubmann.casa
    - restserver.backup.hubmann.casa
    - traefik.backup.hubmann.casa
```

Each configured hostname produces an AdGuard rule of the form
`|hostname|$dnsrewrite=NOERROR;A;address,dnstype=A`. Sync manages only the
section enclosed by its dedicated begin/end comments in AdGuard Home's user
rules. That block's comment explains that the A-only match preserves SOA
lookups required for ACME DNS-01; rules outside the block are retained.

Do not configure the same hostname under both `permanent` (AdGuard DNS
rewrites) and `custom_filtering_rules`. The helper warns and aborts before
making API calls so the conflicting configuration can be fixed. Move such
hosts out of `permanent` and into `custom_filtering_rules`.

For Traefik, use a conventional DNS resolver address, for example
`192.168.2.1:53`, and the current `propagation.delayBeforeChecks` option (for
example, `30s`). The resolver must return the zone's SOA record while AdGuard
continues to return the configured private A answers.

# Thoughts

How to restict api access to only dedicated user and api path?

