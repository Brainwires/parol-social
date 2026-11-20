# Abuse log and fail2ban

The relay image's nginx (both `server/nginx.conf`, the signaling-only default, and `server/nginx.relay.conf`) writes one access
log, the **abuse log**, at `/var/log/nginx/parolnet/access.log` inside the container (`/var/log/parolnet/access.log` on the host
with the `docker-compose.yml` mounts). Each line holds the client address (`CF-Connecting-IP` behind Cloudflare, else the socket
address), method, path **without the query string** (so PeerIds in URLs are never logged), status, body size, request time and
user agent:

```
203.0.113.7 - [20/Nov/2026:19:04:11 +0000] "GET /ws HTTP/1.1" 429 0 rt=0.000 "Mozilla/5.0 ..."
```

nginx answers per-client limit overflows with 429 (`limit_req_status` / `limit_conn_status`).

## Why bans live in nginx, not in the host firewall

parol.social is reached through a Cloudflare tunnel: every request arrives at the container from `cloudflared` on the host, so a
host firewall rule against a client address matches nothing, and a rule against the connection source would block cloudflared
(and so everyone). The real client address is only known inside nginx (`CF-Connecting-IP`). The ban list is therefore an nginx
`geo` map: nginx includes `/etc/nginx/banned/*.conf` (one `<ip> 1;` per line) and answers a banned client 403.

The image creates `/etc/nginx/banned` empty, so the include glob is valid without any ban file. **An operator without fail2ban
can leave `/etc/parolnet/banned` (the host side of the mount) empty**: nothing is banned and everything else works.

## Host setup (fail2ban)

Files in `ops/fail2ban/` (the versions running on biscuits):

| File | Install as |
| --- | --- |
| `parolnet.conf` (filter: 429 / 403 / 400 responses and scanner paths) | `/etc/fail2ban/filter.d/parolnet.conf` |
| `parolnet-nginx-deny.conf` (action: append / remove `<ip> 1;` in `/etc/parolnet/banned/fail2ban.conf`, then `docker exec parolnet-parolnet-1 nginx -s reload`) | `/etc/fail2ban/action.d/parolnet-nginx-deny.conf` |
| `jail-parolnet.conf` (jail: polling backend, 30 hits in 60 s, 1 h ban) | `/etc/fail2ban/jail.d/parolnet.conf` |
| `logrotate-parolnet` (daily, 14 kept, compressed, copytruncate) | `/etc/logrotate.d/parolnet` |

```
sudo mkdir -p /var/log/parolnet /etc/parolnet/banned
sudo install -m 0644 ops/fail2ban/parolnet.conf /etc/fail2ban/filter.d/parolnet.conf
sudo install -m 0644 ops/fail2ban/parolnet-nginx-deny.conf /etc/fail2ban/action.d/parolnet-nginx-deny.conf
sudo install -m 0644 ops/fail2ban/jail-parolnet.conf /etc/fail2ban/jail.d/parolnet.conf
sudo install -m 0644 ops/fail2ban/logrotate-parolnet /etc/logrotate.d/parolnet
docker compose up -d
sudo systemctl reload fail2ban
sudo fail2ban-client status parolnet
```

Notes:

- The action addresses the container by name (`parolnet-parolnet-1`, the compose default for this repo checked out as
  `parolnet`); adjust it if your project or service name differs.
- fail2ban strips the matched date before applying `failregex`, which is why the regex accepts empty brackets (`\[[^\]]*\]`).
- `copytruncate` keeps nginx writing to the same file descriptor, so no reopen signal is needed.
- Unban by hand: `sudo fail2ban-client set parolnet unbanip <ip>`.
- If `CF-Connecting-IP` can reach nginx without Cloudflare in front, a client can forge it (and so its log address and ban key);
  restrict the published port to the tunnel in that case.
