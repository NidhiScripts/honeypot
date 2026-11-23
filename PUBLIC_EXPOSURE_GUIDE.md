# Making Snare Publicly Accessible - Security Guide

## ⚠️ IMPORTANT: Direct Exposure is DANGEROUS

**DO NOT** port-forward port 8080 directly on your home router. Your laptop would be exposed to attacks beyond the honeypot.

---

## ✅ Safe Method: Use a Cloud Tunnel Service

### **Option 1: Cloudflare Tunnel (Recommended - FREE)**

Cloudflare Tunnel (formerly Argo Tunnel) creates a secure tunnel from your laptop to Cloudflare's edge without exposing your home IP.

#### Setup:
1. **Install cloudflared**:
   ```bash
   brew install cloudflare/cloudflare/cloudflared
   ```

2. **Authenticate**:
   ```bash
   cloudflared tunnel login
   ```

3. **Create a tunnel**:
   ```bash
   cloudflared tunnel create honeypot-snare
   ```

4. **Configure the tunnel** (create `~/.cloudflared/config.yml`):
   ```yaml
   tunnel: <TUNNEL_ID_FROM_STEP_3>
   credentials-file: /Users/suraj/.cloudflared/<TUNNEL_ID>.json

   ingress:
     - hostname: honeypot.yourdomain.com
       service: http://localhost:8080
     - service: http_status:404
   ```

5. **Start the tunnel**:
   ```bash
   cloudflared tunnel run honeypot-snare
   ```

6. **Create DNS record** (via Cloudflare dashboard):
   - Type: CNAME
   - Name: honeypot
   - Target: `<TUNNEL_ID>.cfargotunnel.com`

**Pros**:
- Your home IP remains hidden
- DDoS protection included
- Free tier available
- Can handle massive traffic

**Cons**:
- Requires a domain name (or use a free Cloudflare subdomain)

---

### **Option 2: ngrok (Easiest - FREE tier available)**

ngrok is the fastest way to expose localhost to the internet.

#### Setup:
1. **Install ngrok**:
   ```bash
   brew install ngrok
   ```

2. **Sign up** at https://ngrok.com and get your auth token

3. **Authenticate**:
   ```bash
   ngrok config add-authtoken <YOUR_TOKEN>
   ```

4. **Expose Snare**:
   ```bash
   ngrok http 8080
   ```

5. **Copy the public URL** (e.g., `https://abc123.ngrok.io`)

**Pros**:
- Instant setup (2 minutes)
- No domain required
- Free tier available

**Cons**:
- URL changes every time you restart (unless you pay for a reserved domain)
- Limited to 40 connections/min on free tier

---

### **Option 3: AWS/DigitalOcean Micro Instance (Most Realistic)**

Deploy Snare on a cheap cloud VM ($5/month) instead of your laptop.

#### Why this is best:
- Your laptop stays safe
- You get a real public IP
- Can handle unlimited traffic
- More realistic attack patterns (attackers won't know it's a honeypot)

#### Quick setup:
1. **Spin up a Ubuntu VM** (AWS EC2 t2.micro or DigitalOcean droplet)
2. **Install Snare** on the VM
3. **Configure firewall** to only allow ports 80/443/8080
4. **Forward logs** back to your laptop via SSH tunnel or Filebeat

---

## 🛡️ Safety Measures (Regardless of Method)

1. **Isolate the Honeypot**:
   - Run Snare in Docker to contain any potential exploits
   - Never run honeypots on a machine with personal data

2. **Monitor Resource Usage**:
   - Attackers may try to DoS your honeypot
   - Set up alerts if CPU/bandwidth spikes

3. **Rate Limiting**:
   - Use Cloudflare or ngrok's built-in rate limiting
   - Prevent your laptop from being overwhelmed

4. **Regular Backups**:
   - Backup your honeypot logs regularly
   - Keep your laptop's important data separate

---

## 🎯 Recommended Approach for You

Since you're on a **MacBook Air** (limited resources):

1. **Use ngrok for testing** (next 2 weeks)
2. **If you get good data**, move to a **$5 DigitalOcean VM** for long-term
3. **Keep logs flowing back** to your laptop's ELK stack via Filebeat

---

## 📊 Getting More Attackers

Once public, here's how to attract traffic:

1. **Advertise on Shodan**:
   - Shodan scans the entire internet. Just being online is enough.
   - Expected traffic: 10-50 attacks/day within the first week.

2. **Use Common Vulnerable Paths**:
   - Ensure Snare serves paths like `/wp-admin`, `/admin`, `/.env`
   - Bots specifically target these.

3. **Post on Honeypot Communities** (optional):
   - Reddit: r/netsec
   - Twitter: #Honeypot tag
   - Let researchers know you're collecting data.

---

Would you like me to create an automated script to set up ngrok or Cloudflare Tunnel?
