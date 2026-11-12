# Deploying HiveWatch on a VPS

Deployment takes about 10 minutes and one command. You need a fresh **Ubuntu 22.04/24.04** (or Debian 12) server with a public IPv4 address.

> ⚠️ **Use a dedicated server.** A honeypot deliberately invites attackers. Don't run it on a machine that hosts anything you care about. Only deploy on infrastructure you own or rent.

## 1. Get a server

| Provider | Cost | Notes |
|---|---|---|
| **Oracle Cloud** Always Free | €0 | Ampere/AMD VM. Open the ports in the *VCN Security List* (step 3) |
| **Hetzner** CX22 | ~€4/month | Simple, fast, EU |
| **DigitalOcean / Vultr / Linode** | ~$5/month | Many regions, good for an "attacks per region" comparison |

Pick Ubuntu, add your SSH public key (`~/.ssh/id_ed25519.pub`), and note the public IP.

## 2. Run the installer

```bash
ssh ubuntu@YOUR_SERVER_IP
curl -fsSLO https://raw.githubusercontent.com/vicuvi1/hivewatch-soc/main/deploy/install.sh
less install.sh            # read it first, it runs as root
sudo bash install.sh
```

The installer will:

1. Install Docker, git and the compose plugin.
2. Open the needed ports in the host firewall (ufw / iptables).
3. Add your **real** SSH on port **22222** while keeping 22 open.
4. **Stop and ask you to test** `ssh -p 22222 ubuntu@YOUR_SERVER_IP` in a second terminal. Nothing risky happens until you type `yes`.
5. Hand port 22 to the honeypot, generate a random dashboard token, and start the containers.

If the test login fails, answer anything other than `yes`. The script stops and your SSH stays on port 22.

## 3. Open the cloud firewall

Most providers have a firewall *outside* the VM. Allow inbound TCP on:

```
22222 (your admin SSH)   22  23  80  3389  5900  3306  6379  9200 (honeypot)
```

- **Oracle:** Networking → VCN → Security Lists → Add Ingress Rules (source `0.0.0.0/0`)
- **AWS:** EC2 → Security Groups → Inbound rules
- **Hetzner / DO:** Firewalls → Inbound

Do this **before** typing `yes` in step 2, or the port 22222 test will fail.

## 4. Open the dashboard

The dashboard only listens on the server's localhost. Reach it with an SSH tunnel from your own computer:

```bash
ssh -N -L 8000:localhost:8000 -p 22222 ubuntu@YOUR_SERVER_IP
```

Then open `http://localhost:8000/?token=YOUR_TOKEN`. The installer prints the full link at the end. To see it again:

```bash
sudo grep HW_DASH_TOKEN /opt/hivewatch-soc/.env
```

Tip: add this to `~/.ssh/config` on your computer, and `ssh hivewatch` will open both the tunnel and an admin shell:

```
Host hivewatch
    HostName YOUR_SERVER_IP
    User ubuntu
    Port 22222
    LocalForward 8000 localhost:8000
```

## 5. Optional extras

Edit `/opt/hivewatch-soc/.env`, then run `sudo docker compose up -d` in that folder.

- `ABUSEIPDB_API_KEY`: free key from abuseipdb.com. Adds a reputation score to every attacker.
- `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`: phone alerts for high/critical detections. Create the bot with @BotFather; get your chat id from @userinfobot.

## Operations

```bash
cd /opt/hivewatch-soc
sudo docker compose logs -f          # live logs
sudo bash deploy/update.sh           # pull the latest version (data is kept)
sudo bash deploy/uninstall.sh        # stop it and give port 22 back to sshd
sudo bash deploy/uninstall.sh --purge   # ...and delete the captured data
```

Export what you caught: `http://localhost:8000/api/iocs?fmt=csv` (through the tunnel).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ssh -p 22222` times out | Port 22222 isn't open in the **cloud** firewall (step 3) |
| Dashboard shows no events | Check that ports 22/23/80 are open in the cloud firewall. Test from outside: `nc -vz YOUR_SERVER_IP 23` |
| `docker compose up` fails with "port 22 in use" | Real sshd still holds 22: `sudo ss -ltnp \| grep :22`, then re-run the installer |
| Locked out | Use the provider's web/serial console. Delete `/etc/ssh/sshd_config.d/00-hivewatch-admin-port.conf` and `/etc/systemd/system/ssh.socket.d/hivewatch.conf`, then `systemctl daemon-reload && systemctl restart ssh.socket ssh` |
