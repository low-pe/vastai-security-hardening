# Security Audit Script

Comprehensive security auditing tool for Ubuntu servers hosting on vast.ai.

## Features

This script performs **non-invasive, read-only security checks** without interfering with vast.ai operations.

### Check Categories

#### 🔐 SSH Security
- Default port 22 usage
- Password authentication enabled/disabled
- Root login permissions
- Empty password permissions
- MaxAuthTries configuration

#### 🛡️ Firewall & Network
- UFW firewall status and rules
- Open ports listening on all interfaces
- Potentially risky exposed services

#### 👥 User & Access Control
- Users with empty passwords
- Accounts with UID 0 (root equivalents)
- NOPASSWD sudo configurations
- SSH authorized_keys permissions and ownership

#### 📦 System Updates
- Pending security updates
- Available package upgrades
- Unattended-upgrades configuration

#### 📁 File System Security
- World-writable files in system directories
- SUID binaries (especially unusual ones)

#### 📊 Logging & Auditing
- Failed login attempt counts
- Auditd daemon status

#### 🔒 System Hardening
- fail2ban intrusion prevention system
- AppArmor/SELinux mandatory access control
- IP forwarding configuration
- Core dump settings
- Password aging policies

#### 🐳 Docker Security (vast.ai specific)
- Docker socket permissions
- Docker group membership

## Usage

### Basic Audit
```bash
sudo python3 security-audit.py
```

### Verbose Mode (shows detailed info)
```bash
sudo python3 security-audit.py -v
```

### JSON Output (for automation)
```bash
sudo python3 security-audit.py -j > audit-results.json
```

## Exit Codes

- `0` - No critical or high-priority issues (medium/low issues may exist)
- `1` - High-priority issues found
- `2` - Critical issues found

## Severity Levels

- **CRITICAL** (🔴 Red) - Immediate action required (e.g., empty passwords, UID 0 accounts)
- **HIGH** (🟡 Yellow) - Should be addressed soon (e.g., password auth enabled, root login allowed)
- **MEDIUM** (🔵 Blue) - Recommended improvements (e.g., default SSH port, many open ports)
- **LOW** (🟢 Green) - Nice to have (e.g., auditd not installed)
- **INFO** (🔵 Cyan) - Informational / best practices

## Example Output

```
============================================================
SSH
============================================================

⚠ [MEDIUM] SSH Default Port
   SSH is using default port 22
   → Change SSH port in /etc/ssh/sshd_config (e.g., Port 2222)

✗ [HIGH] Password Authentication
   SSH password authentication is enabled
   → Set "PasswordAuthentication no" in /etc/ssh/sshd_config

✓ [INFO] Root Login
   Root login disabled or restricted

============================================================
SUMMARY
============================================================

● High Priority: 1
● Medium Priority: 1
● Low Priority: 0
● Checks Passed: 1
```

## What This Script Does NOT Check

To avoid interfering with vast.ai operations, this script **does not** check or flag:

- Docker daemon running (required for vast.ai)
- NVIDIA drivers and GPU access (required for GPU hosting)
- Network forwarding enabled (needed for containers)
- Vast.ai agent processes
- vastai_kaalia user sudo permissions

## Integration with CI/CD

Use exit codes for automated security checks:

```bash
#!/bin/bash
if sudo python3 security-audit.py; then
    echo "Security audit passed"
else
    exit_code=$?
    if [ $exit_code -eq 2 ]; then
        echo "CRITICAL issues found!"
        exit 2
    elif [ $exit_code -eq 1 ]; then
        echo "High-priority issues found"
        exit 1
    fi
fi
```

## Scheduling Regular Audits

Add to crontab for weekly security audits:

```bash
# Run security audit every Sunday at 2 AM
0 2 * * 0 /usr/bin/python3 /root/vast_hardening/security-audit.py -j > /var/log/security-audit-$(date +\%Y\%m\%d).json
```

## Comparison with deploy-vastai-security.py

| Script | Purpose | Actions |
|--------|---------|---------|
| `deploy-vastai-security.py` | **Hardening** - Actively configures security | Makes changes to system |
| `security-audit.py` | **Auditing** - Identifies security issues | Read-only, no changes |

Use `deploy-vastai-security.py` to initially harden your system, then use `security-audit.py` regularly to verify security posture.

## Common Issues & Fixes

### Default SSH Port (MEDIUM)
```bash
# Edit SSH config
sudo nano /etc/ssh/sshd_config
# Change: Port 2222
sudo systemctl restart sshd
```

### Password Authentication Enabled (HIGH)
```bash
# Edit SSH config
sudo nano /etc/ssh/sshd_config
# Set: PasswordAuthentication no
sudo systemctl restart sshd
```

### UFW Firewall Inactive (HIGH)
```bash
# Allow SSH first!
sudo ufw allow 22/tcp  # or your custom SSH port
sudo ufw enable
```

### Pending Security Updates (HIGH)
```bash
sudo apt update
sudo apt upgrade
```

### Enable Unattended Upgrades (MEDIUM)
```bash
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### Install fail2ban (HIGH)
```bash
# Install and enable fail2ban
sudo apt install fail2ban
sudo systemctl enable --now fail2ban

# Create SSH jail configuration
sudo tee /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 5
bantime = 3600
findtime = 600
EOF

# Restart fail2ban
sudo systemctl restart fail2ban

# Check status
sudo fail2ban-client status sshd
```

### Disable Core Dumps (LOW)
```bash
echo "* hard core 0" | sudo tee -a /etc/security/limits.conf
echo "* soft core 0" | sudo tee -a /etc/security/limits.conf
```

### Set Password Aging Policy (LOW)
```bash
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
```

## Requirements

- Python 3.6+
- sudo access
- Standard Linux utilities (grep, find, ss, etc.)

## License

Same as parent project (see LICENSE file)
