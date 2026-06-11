# split-horizon-dns-helper

Helper to maintain rewrite rules for homelab split horizon dns setup.

Reads certificates and/or router rules from [Traefik Proxy](https://traefik.io/traefik) and creates rewrite rules in [AdGuard Home](https://adguard.com/)

See [config.yml.template](config.yml.template) for configuration.

Run as one off or with a scheduler (cron, systemd).

# Thoughts

How to restict api access to only dedicated user and api path?

