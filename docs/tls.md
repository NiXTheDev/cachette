# TLS and reverse proxies

cachette is TLS-only: there is no plaintext listener to forget to disable. This
page covers the two TLS layers you operate and ready-to-adapt recipes for
terminating the client-facing edge.

## The two layers

1. **Client-facing edge** - runners, the Actions toolkit, and `docker buildx`
   connect here. It should present a **CA-trusted** certificate so clients
   validate it without `--insecure` or a custom CA file.
2. **Inter-node leg** - when clustering is on, peers talk to each other over
   pinned mutual TLS. The self-signed node identity certificate is intended for
   exactly this leg; trust there is a fingerprint, not a CA chain. See
   [cluster.md](cluster.md).

Do not confuse them: the built-in identity certificate is self-signed and
unsuitable for runners, while a CA-trusted edge can be layered on top of either.

## Make `external_url` match reality

Whichever edge you use, set `server.external_url` to the public URL runners use:

```toml
[server]
listen = "127.0.0.1:8080"
external_url = "https://cache.example.com"
```

cachette builds the v1 `archiveLocation` and the v2 capability URLs from
`external_url`. Leave it derived from `listen` and clients behind a proxy receive
URLs pointing at the backend (for example `https://127.0.0.1:8080`) that they
cannot reach. The scheme matters too - the derived default is `http://`, so set
`https://` explicitly.

## Supplying your own certificate

To terminate TLS directly on the listener with a CA-trusted certificate, instead
of at a proxy:

```toml
[server]
listen = "0.0.0.0:8080"
external_url = "https://cache.example.com"
tls_cert = "/etc/cachette/tls/fullchain.pem"
tls_key = "/etc/cachette/tls/privkey.pem"
```

`tls_cert` and `tls_key` must be set together. The certificate is used for the
client-facing listener only; peers keep authenticating with the node identity.

## nginx

The proxy connects to cachette over TLS too, so it must trust the backend
certificate or skip verification for the loopback hop. It must also stop
buffering the large chunked uploads.

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
        proxy_pass https://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # cachette's listener is always TLS; this loopback hop is not attacker
        # reachable, so verification of the self-signed backend is skipped.
        proxy_ssl_verify off;
        proxy_ssl_server_name on;
    }
}
NGINX
nginx -t && systemctl reload nginx
```

## Traefik

Traefik can terminate TLS with a Let's Encrypt certificate and route to the
cachette listener over TLS. A dynamic file-provider configuration:

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
        serversTransport: cachette-insecure
        servers:
          - url: "https://127.0.0.1:8080"
  serversTransports:
    cachette-insecure:
      insecureSkipVerify: true
```

Because the backend is TLS, the endpoint is `https://` and the transport skips
verification for the loopback hop. Publish the router on an entrypoint that
serves `:443` (here `websecure`).

## SSH tunnel

For a single runner host with no reverse proxy, an SSH tunnel keeps the edge
inside your trust boundary:

```bash
export CACHETTE_TUNNEL_HOST="cache.example.com"

# Local-forward: reach the remote listener as if it were localhost:8443.
ssh -N -L 8443:127.0.0.1:8080 "$CACHETTE_TUNNEL_HOST"

# The tunnel terminates TLS at cachette's self-signed listener, so -k is needed
# for a manual probe:
curl -k https://127.0.0.1:8443/health

# Reverse-forward alternative, when the listener must appear on the remote host:
ssh -N -R 8080:127.0.0.1:8080 "$CACHETTE_TUNNEL_HOST"
```

Set `external_url` to the URL clients actually use through the tunnel.

## WireGuard

A WireGuard interface gives every runner a private, authenticated path to the
node, so the self-signed certificate is acceptable inside the tunnel. Server
side:

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

With the tunnel up, clients use `https://10.44.0.1:8080` (or the node's
WireGuard address); set `external_url` to match.

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

`curl.exe` on Windows uses Schannel, which cannot complete the handshake against
cachette's built-in listener (the listener requests a client certificate). For a
manual check, inspect the certificate with `openssl`:

```bash
openssl s_client -connect 127.0.0.1:8080 -servername cache.example.com \
  </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

Real Actions clients are unaffected and are the intended way to exercise the
server.
