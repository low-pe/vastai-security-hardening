# Vast.ai Security Hardening

> **Note**: This is an unofficial, community-maintained security tool. It is not affiliated with or endorsed by Vast.ai. Use at your own risk.

A Python script to secure Vast.ai GPU rental hosts by restricting sudo access to only legitimate vast.ai operations.

---

## ⚠️ Important Maintenance Notice

**This script requires ongoing maintenance.** Vast.ai may add new features, scripts, or commands at any time that are not in the current whitelist. When this happens, you will receive Discord alerts for legitimate vast.ai operations being blocked.

**What to do when you receive alerts:**
1. Check `/var/log/sudo-denials.log` to see the blocked command
2. Verify it's a legitimate vast.ai command
3. Update your whitelist by adding the command to `/etc/sudoers.d/vastai-restricted`
4. Check this repository for updates - we maintain the whitelist as vast.ai evolves
5. Consider opening an issue or PR to help other users

**Recommended:** Monitor this repository for updates and periodically check for new vast.ai commands.

---

## Background

Vast.ai's architecture gives container renters near-root access through passwordless sudo (`vastai_kaalia ALL=(ALL) NOPASSWD:ALL`). This script restricts sudo to only legitimate Vast.ai commands while blocking malicious operations.

## Features

- ✅ **Sudo Command Whitelist** - Restricts `vastai_kaalia` to only approved commands
- ✅ **Discord Monitoring** - Real-time alerts for blocked sudo attempts
- ✅ **Crontab Monitoring** - Alerts when crontab is modified
- ✅ **Core Dump Limits** - Restricts core file sizes
- ✅ **Multi-Server Deployment** - Deploy to multiple hosts simultaneously
- ✅ **Dry Run Mode** - Test changes before applying
- ✅ **Uninstall Support** - Clean removal of security hardening

## Quick Start

### Deploy to current server (interactive)
```bash
./deploy-vastai-security.py
```

The script will:
1. Auto-detect current server
2. Prompt for Discord webhook URL
3. Show interactive feature menu
4. Deploy security hardening

### Deploy to remote servers
```bash
./deploy-vastai-security.py \
  --servers server1,server2,server3 \
  --webhook https://discord.com/api/webhooks/YOUR_WEBHOOK \
  --all
```

### Deploy specific features
```bash
./deploy-vastai-security.py \
  --servers myserver \
  --webhook https://discord.com/api/webhooks/YOUR_WEBHOOK \
  --sudo-restrictions \
  --discord-monitoring
```

### Update existing deployment
When vast.ai adds new commands that need to be whitelisted, download the latest script and re-run with `--update`:
```bash
# Download latest version
wget https://raw.githubusercontent.com/low-pe/vastai-security-hardening/main/deploy-vastai-security.py
chmod +x deploy-vastai-security.py

# Re-deploy with --update flag to restart services
./deploy-vastai-security.py \
  --servers myserver \
  --webhook https://discord.com/api/webhooks/YOUR_WEBHOOK \
  --all \
  --update
```
The `--update` flag restarts monitoring services immediately, ensuring updated whitelists and filters take effect right away.

## Installation

### Prerequisites
- Python 3.6+
- SSH access to target servers (passwordless SSH key recommended)
- Root/sudo access on target servers
- Discord webhook URL (optional, for monitoring)

### Setup
```bash
# Download script
wget https://raw.githubusercontent.com/low-pe/vastai-security-hardening/main/deploy-vastai-security.py
chmod +x deploy-vastai-security.py

# Deploy
./deploy-vastai-security.py --servers myserver --webhook YOUR_WEBHOOK --all
```

## Usage

### Interactive Mode
```bash
./deploy-vastai-security.py
```

### Command-Line Options
```
Options:
  --servers SERVERS         Comma-separated list of servers
  --webhook WEBHOOK         Discord webhook URL for alerts
  --dry-run                 Show what would be done without making changes

  --all                     Deploy all features
  --update                  Update mode: restart services to apply changes immediately
  --interactive             Interactive feature selection
  --sudo-restrictions       Deploy sudo command whitelist
  --discord-monitoring      Deploy Discord alerts for blocked commands
  --crontab-monitoring      Deploy crontab change monitoring
  --core-limits             Deploy core dump size limits

  --uninstall              Remove all security hardening
  --restore-permissive     Restore permissive sudo when uninstalling
```

## Features Detail

### 1. Sudo Command Whitelist

Replaces `vastai_kaalia ALL=(ALL) NOPASSWD:ALL` with a whitelist of approved commands:

**Allowed commands:**
- Docker management (ps, inspect, logs)
- GPU management (nvidia-smi)
- Network diagnostics (ss, tshark)
- Disk I/O benchmarking (dd, hdparm, rm tmpfiles)
- System diagnostics (journalctl, dmidecode, lshw, fio)
- VM management (virsh, enable_vms.py)
- Process management (kill)
- Script updates (systemd-run for vast.ai updates)

**Blocked commands:**
- Arbitrary script execution (like `/tmp/.malicious_script`)
- Package installation (apt, yum, etc.)
- System modification commands
- Any command not explicitly whitelisted

### 2. Discord Monitoring

Real-time alerts when commands are blocked:

```
🚨 Sudo Access Denied on vast-server
User: vastai_kaalia
Attempted Command: sudo /tmp/.malicious_script
Time: 2025-10-23 01:13:45 UTC
```

### 3. Crontab Monitoring

Alerts when root's crontab is modified (common persistence mechanism).

### 4. Core Dump Limits

Restricts core dump sizes to prevent disk space issues.

## Uninstalling

### Remove security (keep sudo restricted)
```bash
./deploy-vastai-security.py --servers myserver --uninstall
```

### Remove security and restore full sudo access
```bash
./deploy-vastai-security.py --servers myserver --uninstall --restore-permissive
```

## Security Considerations

### Known Limitations

1. **Wildcard Paths** - Some rules use wildcards (e.g., `/var/lib/docker/*`) which may allow path traversal for reading files, but not code execution.

2. **Platform Dependencies** - The whitelist includes commands necessary for vast.ai platform operations, including automated updates. This requires trusting the vast.ai infrastructure.

3. **Not a Complete Solution** - This hardens the system but doesn't eliminate all risks. Vast.ai's architecture fundamentally requires giving renters significant system access.

### Best Practices

- Monitor Discord alerts regularly
- Review `/var/log/sudo-denials.log` periodically
- Keep the whitelist updated as vast.ai adds new commands
- Consider the risk/reward of running vast.ai hosting

## Testing

### Dry Run
```bash
./deploy-vastai-security.py --servers myserver --webhook URL --all --dry-run
```

### Test Allowed Command
```bash
ssh myserver "sudo -u vastai_kaalia sudo nvidia-smi -pm 1"
```

### Test Blocked Command
```bash
ssh myserver "sudo -u vastai_kaalia sudo whoami"
# Should fail with "command not allowed"
```

## Monitoring

### Check Denied Commands
```bash
ssh myserver "sudo tail -f /var/log/sudo-denials.log"
```

### Check Monitoring Service Status
```bash
ssh myserver "sudo systemctl status sudo-monitor.timer"
ssh myserver "sudo systemctl status crontab-monitor.service"
```

## Troubleshooting

### Script blocks legitimate vast.ai commands?
1. Check `/var/log/sudo-denials.log` for the exact command
2. Add the command to the whitelist
3. Report the issue so we can update the default whitelist

### Discord alerts not working?
1. Verify webhook URL is correct
2. Check service status: `systemctl status sudo-monitor.timer`
3. Check logs: `journalctl -u sudo-monitor.service`

### Want to undo changes?
```bash
# Restore from backup
sudo cp /etc/sudoers.backup.TIMESTAMP /etc/sudoers

# Or use uninstall
./deploy-vastai-security.py --servers myserver --uninstall --restore-permissive
```

## Contributing

Contributions welcome! If you find commands that should be whitelisted or have security improvements, please open an issue or PR.

## License

MIT License - See LICENSE file

## Disclaimer

This script hardens vast.ai hosts but cannot eliminate all risks. Use at your own discretion. The authors are not responsible for any damage or losses.

## Support

- Issues: https://github.com/low-pe/vastai-security-hardening/issues
- Vast.ai: https://vast.ai
