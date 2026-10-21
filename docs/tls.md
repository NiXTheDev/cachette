# TLS and reverse proxies

cachette's main listener is plaintext HTTP unless `[server] tls_cert`/`tls_key`
are configured: TLS on the edge is the proxy's job by default, and the public
certificates stay where the public traffic is. This page covers the three TLS
surfaces you operate and ready-to-adapt recipes for the edge.

## The TLS surfaces

1. **Client-facing edge** - runners, the Actions toolkit, and `docker buildx`
   connect here. It should present a **CA-trusted** certificate so clients
   validate it without `--insecure` or a custom CA file. Either a reverse proxy
   holds that certificate and forwards to the plaintext listener, or you supply
   the pair to `[server]` and the listener terminates TLS itself.
2. **Inter-node leg** - when clustering is on, peers talk to each other over a
   dedicated port (`[cluster] listen`, default `0.0.0.0:8081`) that **always**
   terminates TLS with the pinned node identity. Trust there is a fingerprint,
   not a CA chain. See [cluster.md](cluster.md).
3. **Loopback/proxy hop** - what a proxy forwards *to* cachette: plaintext
   `http://` by default, `https://` with verification skipped only if you
   enabled listener TLS.

Do not confuse them: the self-signed identity certificate belongs to the
cluster port; runners reach a CA-trusted edge, whatever sits behind it.

## Make `external_url` match reality

By default the main listener is plain HTTP, so `external_url` derived from
`listen` starts with `http://`. Whatever your edge looks like, set
`server.external_url` to the public URL runners use:

```toml
[server]
listen = "127.0.0.1:8080"
external_url = "https://cache.example.com"
```

cachette builds the v1 `archiveLocation` and the v2 capability URLs from
`external_url`. Leave it derived from `listen` and clients behind a proxy receive
URLs pointing at the backend (for example `http://127.0.0.1:8080`) that they
cannot reach.

## Supplying your own certificate

To terminate TLS directly on the main listener, instead of at a proxy, supply
the pair:

```toml
[server]
listen = "0.0.0.0:8080"
external_url = "https://cache.example.com"
tls_cert = "/etc/cachette/tls/fullchain.pem"
tls_key = "/etc/cachette/tls/privkey.pem"
```

`tls_cert` and `tls_key` must be set together; with both unset the listener is
plaintext HTTP. The certificate is used for the client-facing listener only;
peers keep connecting to the dedicated cluster port and authenticating with the
node identity.

## nginx

The default upstream is plaintext HTTP, so the proxy hop needs no TLS wiring.
It must still stop buffering the large chunked uploads.

```bash
# /etc/nginx/conf.d/cachette.conf
cat > /etc/nginx/conf.d/cachette.conf <<'NGINX'
server {
    listen 443 ssl;
    server_name cache.example.com;

    ssl_certificate     /etc/letsencrypt/live/cache.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cache.example.com/privkey.pem;

    # Cache uploads are large and long-lived: disable buffering, raise timeouts.
    client_max_body_size 0;
    proxy_request_buffering off;
    proxy_buffering off;
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX
nginx -t && systemctl reload nginx
```

If you enabled `[server] tls_cert`/`tls_key` instead, switch the upstream to
TLS and skip verification for the loopback hop:

```nginx
location / {
    proxy_pass https://127.0.0.1:8080;
    # The backend presents the configured certificate; verification is
    # skipped for the loopback hop, which is not attacker reachable.
    proxy_ssl_verify off;
    proxy_ssl_server_name on;
}
```

## Traefik

Traefik terminates TLS with a Let's Encrypt certificate and forwards to the
plaintext listener:

```yaml
http:
  routers:
    cachette:
      rule: "Host(`cache.example.com`)"
      entryPoints: ["websecure"]
      service: cachette
      tls:
        certResolver: letsencrypt
  services:
    cachette:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
```

With `[server]` TLS enabled instead, point the service at `https://` and add an
`serversTransport` with `insecureSkipVerify: true` for the loopback hop.

## SSH tunnel

For a single runner host with no reverse proxy, an SSH tunnel keeps the edge
inside your trust boundary:

```bash
export CACHETTE_TUNNEL_HOST="cache.example.com"

# Local-forward: reach the remote listener as if it were localhost:8443.
ssh -N -L 8443:127.0.0.1:8080 "$CACHETTE_TUNNEL_HOST"

# The default listener is plaintext, so a plain curl works:
curl http://127.0.0.1:8443/health

# Reverse-forward alternative, when the listener must appear on the remote host:
ssh -N -R 8080:127.0.0.1:8080 "$CACHETTE_TUNNEL_HOST"
```

With `[server]` TLS enabled the probe becomes `curl -k https://...`. Set
`external_url` to the URL clients actually use through the tunnel.

## WireGuard

A WireGuard interface gives every runner a private, authenticated path to the
node, so plaintext inside the tunnel is fine. Server side:

```bash
# /etc/wireguard/wg0.conf (server)
cat > /etc/wireguard/wg0.conf <<'WG'
[Interface]
Address = 10.44.0.1/24
ListenPort = 51820
PrivateKey = <server-private-key>

[Peer]
# runner host
PublicKey = <runner-public-key>
AllowedIPs = 10.44.0.2/32
WG
wg-quick up wg0
```

With the tunnel up, clients use `http://10.44.0.1:8080` (or the node's
WireGuard address); set `external_url` to match. Enable `[server]` TLS if you
want encryption beyond the WireGuard fabric.

## Rate limiting

cachette has no application-level rate limiter and never returns `429` for
overload - a node that cannot admit a write answers `503`. Put request limits at
the proxy or network edge. With nginx, the zones belong in the `http {}` block
and the limits in the `location {}`:

```bash
# In http {} (for example /etc/nginx/nginx.conf):
#   limit_req_zone  $binary_remote_addr zone=cachette_req:10m rate=20r/s;
#   limit_conn_zone $binary_remote_addr zone=cachette_conn:10m;
#
# Then inside the cachette location {}:
#   limit_req  zone=cachette_req burst=40 nodelay;
#   limit_conn cachette_conn 8;
nginx -t && systemctl reload nginx
```

Raise the limits for chunked uploads, which issue many small `PATCH` requests.

## A note on Windows clients

With the default plaintext listener, Windows `curl.exe` works fine. If you
enable `[server]` TLS with a self-served certificate, Windows `curl.exe`
(Schannel) may reject it depending on trust and algorithm details; a
CA-trusted certificate through the `[server]` pair avoids the whole class. For
a manual check of the served certificate (cluster port or TLS-enabled main
listener), inspect it with `openssl`:

```bash
openssl s_client -connect 127.0.0.1:8081 -servername node \
  </dev/null 2>/dev/null | openssl x509 -noout -subject -dates -fingerprint
```

Real Actions clients are unaffected and are the intended way to exercise the
server.
