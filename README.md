# split-horizon-dns-helper

Helper to maintain rewrite rules for homelab split horizon dns setup

Reads certificates from [Traefik Proxy](https://traefik.io/traefik) and creates rewrite rules in [AdGuard Home](https://adguard.com/en/welcome.html)

See config.yml for configuration.

Run as one off or with a scheduler (cron, systemd).

# Thoughts

Switch traefik api to /api/http/routers? Avoids old domains from unused certs.
Need to add /api/tcp and /api/udp too then.

How to restict api access to only dedicated user and api path?

