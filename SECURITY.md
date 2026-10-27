# Security policy

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private reporting:
**Security → Report a vulnerability** in this repository.

Include the version (image tag or chart version), a description, and steps to reproduce. You can
expect an acknowledgement within a few days.

## Threat model in short

AmberVentory holds an SSH private key and produces a map of the vulnerabilities in your network.
Treat it like a jump host:

- Always enable authentication (`AMBER_USER` / `AMBER_PASSWORD`, or `auth.*` in the Helm chart) and put TLS in front of it.
- Do not expose it to the internet. Restrict access with a NetworkPolicy or a firewall.
- Use a dedicated read-only SSH account on the target hosts.
- The service never writes to the scanned hosts (except the apt cache if you opt in to `apt-get update`).
