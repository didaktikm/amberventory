# amberventory

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.1.0](https://img.shields.io/badge/AppVersion-0.1.0-informational?style=flat-square)

Debian fleet inventory and vulnerability report (Ansible, nmap, Debian Security Tracker, CISA KEV, EPSS) with a web UI

**Homepage:** <https://github.com/didaktikm/amberventory>

## TL;DR

```bash
helm install amberventory oci://ghcr.io/didaktikm/charts/amberventory \
  --namespace amberventory --create-namespace
```

The chart creates a Deployment (one replica), a Service, a PersistentVolumeClaim for `/data`
and a Secret with a generated admin password. Print the password and open the interface:

```bash
kubectl -n amberventory get secret amberventory -o jsonpath='{.data.password}' | base64 -d; echo
kubectl -n amberventory port-forward svc/amberventory 8080:80
```

## Requirements

- Kubernetes >=1.25.0-0
- Helm 3.8+ (OCI registries) or Helm 4
- A StorageClass that can provide a `ReadWriteOnce` volume (or `persistence.existingClaim`)
- Network paths from the pod to the hosts you want to inventory (SSH, port 22 by default) and, for the
  vulnerability feeds, HTTPS access to `security-tracker.debian.org`, `www.cisa.gov` and `epss.empiricalsecurity.com`
  (or mirrors, see `config.trackerUrl`, `config.kevUrl`, `config.epssUrl`)

## Design decisions

| Topic | What the chart does and why |
|---|---|
| **One replica, `Recreate`** | The application keeps job state and the unlocked SSH key passphrase in memory and stores data in SQLite on a single volume. Two replicas would not share state, and a rolling update would try to mount a `ReadWriteOnce` volume twice. There is no `replicaCount`, HPA or PodDisruptionBudget on purpose. |
| **Authentication on by default** | AmberVentory holds a private SSH key that opens every host in the inventory and can run nmap. The chart enables HTTP basic auth and generates a random password. Disabling it prints a warning in the release notes. |
| **Hardened pod** | Non-root (UID 10001), read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp, no ServiceAccount token. Writable paths `/data`, `/tmp` and `/home/amber` are volumes. nmap runs as an unprivileged user and falls back to a TCP connect scan, which is all that port discovery needs. |
| **Rollout on config change** | Checksums of the ConfigMap and the Secret are pod annotations, so changing values restarts the pod. |
| **Optional Gateway API** | Set `httpRoute.enabled` to use an `HTTPRoute` instead of an Ingress. |

## Common tasks

### Expose through an Ingress with TLS

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
    # Needed only to upload the Debian tracker JSON (about 60 MB) by hand in an air-gapped setup
    nginx.ingress.kubernetes.io/proxy-body-size: 128m
  hosts:
    - host: amberventory.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: amberventory-tls
      hosts:
        - amberventory.example.com
```

### Provide your own credentials

```bash
kubectl -n amberventory create secret generic amberventory-credentials \
  --from-literal=username=admin --from-literal=password='...'
helm upgrade --install amberventory oci://ghcr.io/didaktikm/charts/amberventory -n amberventory \
  --set auth.existingSecret=amberventory-credentials
```

With Argo CD, Flux or `helm template` always set `auth.password` or `auth.existingSecret`:
the chart generates a random password with `lookup`, which these tools cannot do, so the value
would change on every render.

### Scan a network the pod cannot reach

Pods usually sit in an overlay network. If the subnet is reachable from the nodes but not from the pod network,
run the pod in the node network and pin it to a suitable node:

```yaml
hostNetwork: true
nodeSelector:
  kubernetes.io/hostname: node-in-the-right-vlan
```

The application then listens on `config.port` of that node, so restrict access with a firewall or a NetworkPolicy.

### Restrict network access

```yaml
networkPolicy:
  enabled: true
  ingressFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
  egress:
    ports: [22, 443]   # add the SSH ports you actually use
```

### Use a private registry or a private GHCR package

A package published to the GitHub Container Registry is private until you change its visibility.
Either make the package public or create a pull secret:

```bash
kubectl -n amberventory create secret docker-registry ghcr \
  --docker-server=ghcr.io --docker-username=<user> --docker-password=<token with read:packages>
helm upgrade --install amberventory ... --set 'imagePullSecrets[0].name=ghcr'
```

### Verify host keys

Put the output of `ssh-keyscan` for your hosts into `knownHosts`, then tick *Verify host key*
in the web interface:

```yaml
knownHosts: |
  10.0.0.11 ssh-ed25519 AAAA...
  10.0.0.12 ssh-ed25519 AAAA...
```

### The SSH key

The key is uploaded through the web interface and stored in `/data/keys` on the persistent volume
(mode 600). It is not part of the chart values. Without persistence it has to be uploaded again
after every restart.

## Upgrade, test, uninstall

```bash
helm upgrade amberventory oci://ghcr.io/didaktikm/charts/amberventory -n amberventory --reuse-values
helm test amberventory -n amberventory      # calls /healthz from inside the cluster
helm uninstall amberventory -n amberventory # the PVC is removed with the release unless annotated with helm.sh/resource-policy: keep
```

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity rules |
| auth.enabled | bool | `true` | Enable HTTP basic authentication in the application (`/healthz` stays open for probes) |
| auth.existingSecret | string | `""` | Name of an existing Secret with the credentials |
| auth.existingSecretPasswordKey | string | `"password"` | Key with the password in `existingSecret` |
| auth.existingSecretUserKey | string | `"username"` | Key with the username in `existingSecret` |
| auth.password | string | `""` | Password. If empty, a random one is generated on first install and kept on upgrades (only works with `helm install/upgrade`. For `helm template`/GitOps set a value or `existingSecret`) |
| auth.username | string | `"admin"` | Username. Ignored when `existingSecret` is set |
| commonAnnotations | object | `{}` | Annotations added to every resource |
| commonLabels | object | `{}` | Labels added to every resource |
| config.epssUrl | string | `""` | Mirror(s) of the EPSS scores file, comma-separated (`AMBER_EPSS_URL`) |
| config.feedTtl | int | `21600` | Vulnerability feed refresh interval in seconds (`AMBER_FEED_TTL`) |
| config.forks | int | `10` | Parallel SSH sessions (`AMBER_FORKS`). Every fork is a separate Python process (rough estimate: 50-80 MiB each), keep this in line with the memory limit |
| config.jobTimeout | int | `1800` | Maximum duration of one collection job in seconds (`AMBER_JOB_TIMEOUT`) |
| config.kevUrl | string | `""` | Mirror of the CISA KEV catalog (`AMBER_KEV_URL`) |
| config.maxScanHosts | int | `4096` | Maximum number of addresses nmap may scan in one request (`AMBER_MAX_SCAN_HOSTS`) |
| config.nvdMaxPerRun | int | `300` | Maximum CVEs enriched from NVD per run (`AMBER_NVD_MAX`) |
| config.port | int | `8080` | Port the application listens on |
| config.sshTimeout | int | `15` | SSH connect timeout in seconds (`AMBER_SSH_TIMEOUT`) |
| config.trackerUrl | string | `""` | Mirror of the Debian Security Tracker JSON (`AMBER_TRACKER_URL`) |
| config.watchlist | string | `""` | Comma-separated glob list of packages highlighted in reports (`AMBER_WATCHLIST`). Empty means the built-in list |
| dnsPolicy | string | `""` | DNS policy. With `hostNetwork: true` and an empty value `ClusterFirstWithHostNet` is used |
| extraEnv | list | `[]` | Extra environment variables (list of `EnvVar`) |
| extraEnvFrom | list | `[]` | Extra `envFrom` sources (ConfigMap or Secret references) |
| extraVolumeMounts | list | `[]` | Extra volume mounts for the application container |
| extraVolumes | list | `[]` | Extra volumes |
| fullnameOverride | string | `""` | Override the full resource name |
| hostNetwork | bool | `false` | Run in the node network namespace. Use it when the subnet you scan is reachable from nodes but not from the pod network |
| httpRoute.annotations | object | `{}` | HTTPRoute annotations |
| httpRoute.enabled | bool | `false` | Create a Gateway API HTTPRoute |
| httpRoute.hostnames | list | `[]` | Hostnames matched by the route |
| httpRoute.parentRefs | list | `[]` | Gateways the route attaches to |
| httpRoute.rules | list | `[]` | Route rules. Defaults to forwarding `/` to the Service |
| image.digest | string | `""` | Image digest (`sha256:...`). Takes precedence over `tag` when set |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| image.repository | string | `"ghcr.io/didaktikm/amberventory"` | Image repository |
| image.tag | string | `""` | Image tag. Defaults to the chart `appVersion` |
| imagePullSecrets | list | `[]` | Pull secrets for a private registry. A new GitHub Container Registry package is private until you make it public |
| ingress.annotations | object | `{}` | Ingress annotations. Uploading the Debian tracker JSON (about 60 MB) needs a larger body limit, for example `nginx.ingress.kubernetes.io/proxy-body-size: 128m` |
| ingress.className | string | `""` | IngressClass name |
| ingress.enabled | bool | `false` | Create an Ingress |
| ingress.hosts | list | `[{"host":"amberventory.example.com","paths":[{"path":"/","pathType":"Prefix"}]}]` | Ingress hosts and paths |
| ingress.tls | list | `[]` | Ingress TLS configuration |
| knownHosts | string | `""` | Content of a `known_hosts` file mounted at `~/.ssh/known_hosts`. Needed for the "Verify host key" option |
| livenessProbe.enabled | bool | `true` | Enable the liveness probe |
| livenessProbe.failureThreshold | int | `3` | Failed liveness checks before the container is restarted |
| livenessProbe.httpGet.path | string | `"/healthz"` | Liveness probe HTTP path |
| livenessProbe.httpGet.port | string | `"http"` | Liveness probe port (named container port) |
| livenessProbe.periodSeconds | int | `20` | Liveness probe period in seconds |
| livenessProbe.timeoutSeconds | int | `5` | Liveness probe timeout in seconds |
| nameOverride | string | `""` | Override the chart name used in resource names |
| networkPolicy.egress.dns | bool | `true` | Allow DNS queries (port 53 TCP/UDP) to any destination |
| networkPolicy.egress.extraRules | list | `[]` | Additional egress rules (list of NetworkPolicyEgressRule) |
| networkPolicy.egress.ports | list | `[22,443]` | Destination TCP ports allowed to any address: SSH to the hosts, HTTPS for the vulnerability feeds. Add the ports you scan |
| networkPolicy.enabled | bool | `false` | Create a NetworkPolicy |
| networkPolicy.ingressFrom | list | `[]` | Sources allowed to reach the application (list of NetworkPolicyPeer). Empty allows all sources |
| nodeSelector | object | `{}` | Node selector |
| nvd.apiKey | string | `""` | NVD API key. Optional: speeds up CVSS enrichment about ten times |
| nvd.existingSecret | string | `""` | Name of an existing Secret with the NVD API key |
| nvd.existingSecretKey | string | `"api-key"` | Key with the API key in `existingSecret` |
| persistence.accessModes | list | `["ReadWriteOnce"]` | Access modes. The application must run as a single replica, so `ReadWriteOnce` is enough |
| persistence.annotations | object | `{}` | PVC annotations. Add `helm.sh/resource-policy: keep` to retain the volume after `helm uninstall` |
| persistence.enabled | bool | `true` | Persist `/data` (SSH key, reports, vulnerability database). If disabled an `emptyDir` is used and everything is lost on restart |
| persistence.existingClaim | string | `""` | Use an existing PersistentVolumeClaim |
| persistence.size | string | `"5Gi"` | Volume size |
| persistence.storageClass | string | `""` | StorageClass. `-` disables dynamic provisioning, empty uses the cluster default |
| podAnnotations | object | `{}` | Pod annotations |
| podLabels | object | `{}` | Pod labels |
| podSecurityContext | object | `{"fsGroup":10001,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":10001,"runAsNonRoot":true,"runAsUser":10001,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod security context. UID/GID 10001 is the `amber` user baked into the image |
| priorityClassName | string | `""` | PriorityClass name |
| proxy.http | string | `""` | `HTTP_PROXY` for feed downloads. Do not put credentials here, use `extraEnvFrom` with a Secret |
| proxy.https | string | `""` | `HTTPS_PROXY` for feed downloads |
| proxy.noProxy | string | `""` | `NO_PROXY` |
| readinessProbe.enabled | bool | `true` | Enable the readiness probe |
| readinessProbe.failureThreshold | int | `3` | Failed readiness checks before the pod is taken out of the Service |
| readinessProbe.httpGet.path | string | `"/healthz"` | Readiness probe HTTP path |
| readinessProbe.httpGet.port | string | `"http"` | Readiness probe port (named container port) |
| readinessProbe.periodSeconds | int | `10` | Readiness probe period in seconds |
| readinessProbe.timeoutSeconds | int | `5` | Readiness probe timeout in seconds |
| resources | object | `{"limits":{"memory":"2Gi"},"requests":{"cpu":"100m","memory":"512Mi"}}` | Resource requests and limits. These are estimates, not measurements: memory grows with `config.forks` and the size of the fleet |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true}` | Container security context. Writable paths (`/data`, `/tmp`, `/home/amber`) are mounted as volumes |
| service.annotations | object | `{}` | Service annotations |
| service.nodePort | string | `nil` | Node port, for `type: NodePort` |
| service.port | int | `80` | Service port |
| service.type | string | `"ClusterIP"` | Service type |
| serviceAccount.annotations | object | `{}` | ServiceAccount annotations |
| serviceAccount.automount | bool | `false` | Mount the ServiceAccount token. The application does not use the Kubernetes API |
| serviceAccount.create | bool | `true` | Create a ServiceAccount |
| serviceAccount.name | string | `""` | Name of the ServiceAccount. Generated from the release name if empty |
| startupProbe.enabled | bool | `true` | Enable the startup probe |
| startupProbe.failureThreshold | int | `30` | Failed startup checks before the container is restarted |
| startupProbe.httpGet.path | string | `"/healthz"` | Startup probe HTTP path |
| startupProbe.httpGet.port | string | `"http"` | Startup probe port (named container port) |
| startupProbe.periodSeconds | int | `5` | Startup probe period in seconds |
| terminationGracePeriodSeconds | int | `30` | Pod termination grace period in seconds |
| tolerations | list | `[]` | Tolerations |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
