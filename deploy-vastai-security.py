#!/usr/bin/env python3
"""
Vast.ai Security Hardening Deployment Script

Version: 1.0.0
Author: Vast.ai Security Contributors
License: MIT
Repository: https://github.com/YOUR_USERNAME/vastai-security

Modular security deployment with optional features

Usage:
    # Interactive mode
    python3 deploy-vastai-security.py --servers myserver --webhook https://... --interactive

    # Deploy all features
    python3 deploy-vastai-security.py --servers prod1 --webhook https://... --all

    # Deploy specific features
    python3 deploy-vastai-security.py --servers prod1,prod2,prod3 --webhook https://... \\
        --sudo-restrictions --discord-monitoring

    # Uninstall security hardening
    python3 deploy-vastai-security.py --servers myserver --uninstall

    # Uninstall and restore permissive sudo
    python3 deploy-vastai-security.py --servers myserver --uninstall --restore-permissive

Examples:
    # Deploy sudo restrictions and monitoring
    ./deploy-vastai-security.py --servers prod1 --webhook URL --sudo-restrictions --discord-monitoring

    # Deploy all security features
    ./deploy-vastai-security.py --servers prod1 --webhook URL --all

    # Remove security hardening (keeps sudo restricted)
    ./deploy-vastai-security.py --servers prod1 --uninstall

    # Remove security hardening and restore full sudo access
    ./deploy-vastai-security.py --servers prod1 --uninstall --restore-permissive
"""

import argparse
import subprocess
import sys
from datetime import datetime

VERSION = "1.0.0"

# Available security features
FEATURES = {
    'sudo_restrictions': 'Sudo Command Whitelist (blocks arbitrary sudo execution)',
    'discord_monitoring': 'Discord Alerts for Blocked Commands',
    'crontab_monitoring': 'Crontab Change Monitoring',
    'core_limits': 'Core Dump Size Restrictions'
}

#############################################################################
# CONFIGURATION TEMPLATES
#############################################################################

SUDOERS_CONTENT = """# Vast.ai restricted sudo permissions
# Created: {date}
# Purpose: Whitelist specific commands, block arbitrary execution

# Docker container management
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/cat /var/lib/docker/*
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/du -d 0 -h /var/lib/docker/*
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/du /var/lib/docker/*
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/docker ps *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/docker inspect *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/docker logs *

# GPU management
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/timeout * /usr/bin/nvidia-smi -pm 1
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/timeout * nvidia-smi -pm 1
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/nvidia-smi -pm 1
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/cat /sys/module/nvidia_drm/parameters/modeset
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/cat /sys/*

# Network monitoring
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/tshark *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/apt-get install * tshark
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/apt-get install -yq tshark

# SSH daemon
vastai_kaalia ALL=(root) NOPASSWD: /usr/sbin/sshd -p *

# System configuration
vastai_kaalia ALL=(root) NOPASSWD: /usr/sbin/sysctl -w kernel.core_pattern=*
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/sed -i * /etc/security/limits.conf

# Diagnostics
vastai_kaalia ALL=(root) NOPASSWD: /usr/sbin/dmidecode *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/timeout * /usr/bin/journalctl *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/timeout * journalctl *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/journalctl *
vastai_kaalia ALL=(root) NOPASSWD: /bin/journalctl *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/fio *

# Vast.ai updates
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/usermod -a -G docker vastai_kaalia
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/cp -f * /usr/local/bin/vastai-run-update
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/chmod a+x /usr/local/bin/vastai-run-update
vastai_kaalia ALL=(root) NOPASSWD: /usr/sbin/logrotate *

# Iptables
vastai_kaalia ALL=(root) NOPASSWD: /usr/sbin/iptables *
vastai_kaalia ALL=(root) NOPASSWD: /usr/sbin/iptables-save *

# VM/Virtualization management
vastai_kaalia ALL=(root) NOPASSWD: /var/lib/vastai_kaalia/enable_vms.py *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/virsh *

# Process management
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/kill *

# Disk I/O benchmarking
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/dd if=/dev/zero of=/var/lib/docker/* *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/dd if=/var/lib/docker/* of=/var/lib/docker/* *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/rm /var/lib/docker/tmpfile*
vastai_kaalia ALL=(root) NOPASSWD: /usr/sbin/hdparm -t *

# Script updates
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemd-run --scope --unit=vastai_script_updater sh -c *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemd-run --scope --unit=vastai_script_updater *

# GPU management (ENABLED variant)
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/nvidia-smi -pm ENABLED

# Network diagnostics
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/ss *

# Hardware info
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/lshw *

# Systemctl service management
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemctl stop vastai
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemctl start vastai
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemctl restart vastai
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemctl status vastai
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemctl enable vastai
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemctl daemon-reload
"""

SUDO_MONITOR_SCRIPT = """#!/bin/bash
# Sudo Denial Monitor
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL}"
HOSTNAME=$(hostname)
LOG_FILE="/var/log/auth.log"
STATE_FILE="/var/tmp/sudo-monitor.state"

[ -f "$STATE_FILE" ] && LAST_LINE=$(cat "$STATE_FILE") || LAST_LINE=0
CURRENT_LINE=$(wc -l < "$LOG_FILE")

if [ "$CURRENT_LINE" -gt "$LAST_LINE" ]; then
    tail -n +$((LAST_LINE + 1)) "$LOG_FILE" | grep "sudo.*vastai_kaalia.*command not allowed" | grep -v "COMMAND=virsh" | grep -v "COMMAND=/var/lib/vastai_kaalia/enable_vms.py" | while read -r line; do
        TIMESTAMP=$(echo "$line" | awk '{print $1, $2, $3}')
        COMMAND=$(echo "$line" | grep -oP "COMMAND=\\K.*" || echo "Unknown")

        if [ -n "$DISCORD_WEBHOOK_URL" ]; then
            curl -s -H "Content-Type: application/json" -X POST -d "{
                \\"embeds\\": [{
                    \\"title\\": \\"🚨 Sudo Denied on $HOSTNAME\\",
                    \\"description\\": \\"Blocked sudo command attempted\\",
                    \\"color\\": 15158332,
                    \\"fields\\": [
                        {\\"name\\": \\"Server\\", \\"value\\": \\"$HOSTNAME\\", \\"inline\\": true},
                        {\\"name\\": \\"User\\", \\"value\\": \\"vastai_kaalia\\", \\"inline\\": true},
                        {\\"name\\": \\"Time\\", \\"value\\": \\"$TIMESTAMP\\", \\"inline\\": false},
                        {\\"name\\": \\"Command\\", \\"value\\": \\"\\`\\`\\`$COMMAND\\`\\`\\`\\", \\"inline\\": false}
                    ],
                    \\"footer\\": {\\"text\\": \\"Security Monitor\\"},
                    \\"timestamp\\": \\"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\\"
                }]
            }" "$DISCORD_WEBHOOK_URL" >/dev/null 2>&1
        fi
        echo "[$(date)] SUDO DENIED: $line" >> /var/log/sudo-denials.log
    done
    echo "$CURRENT_LINE" > "$STATE_FILE"
fi
"""

CRONTAB_MONITOR_SCRIPT = """#!/bin/bash
# Crontab Change Monitor
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL}"
HOSTNAME=$(hostname)
CRONTAB_FILE="/var/spool/cron/crontabs/root"
HASH_FILE="/var/tmp/root-crontab.sha256"

if [ ! -f "$CRONTAB_FILE" ]; then
    exit 0
fi

CURRENT_HASH=$(sha256sum "$CRONTAB_FILE" | awk '{print $1}')

if [ -f "$HASH_FILE" ]; then
    STORED_HASH=$(cat "$HASH_FILE")
    if [ "$CURRENT_HASH" != "$STORED_HASH" ]; then
        # Crontab changed!
        CHANGES=$(diff <(echo "$STORED_HASH") <(echo "$CURRENT_HASH") 2>&1 || echo "Hash mismatch")

        if [ -n "$DISCORD_WEBHOOK_URL" ]; then
            CRONTAB_CONTENT=$(sudo cat "$CRONTAB_FILE" | head -20)
            curl -s -H "Content-Type: application/json" -X POST -d "{
                \\"embeds\\": [{
                    \\"title\\": \\"⚠️ Crontab Modified on $HOSTNAME\\",
                    \\"description\\": \\"Root crontab has been modified\\",
                    \\"color\\": 16776960,
                    \\"fields\\": [
                        {\\"name\\": \\"Server\\", \\"value\\": \\"$HOSTNAME\\", \\"inline\\": true},
                        {\\"name\\": \\"User\\", \\"value\\": \\"root\\", \\"inline\\": true},
                        {\\"name\\": \\"Time\\", \\"value\\": \\"$(date)\\", \\"inline\\": false},
                        {\\"name\\": \\"Current Crontab\\", \\"value\\": \\"\\`\\`\\`$CRONTAB_CONTENT\\`\\`\\`\\", \\"inline\\": false}
                    ],
                    \\"footer\\": {\\"text\\": \\"Crontab Monitor\\"},
                    \\"timestamp\\": \\"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\\"
                }]
            }" "$DISCORD_WEBHOOK_URL" >/dev/null 2>&1
        fi
        echo "[$(date)] CRONTAB CHANGED for vastai_kaalia" >> /var/log/crontab-changes.log
    fi
fi

echo "$CURRENT_HASH" > "$HASH_FILE"
"""

SYSTEMD_SERVICE_TEMPLATE = """[Unit]
Description={description}
After=network.target

[Service]
Type=oneshot
ExecStart={script_path}
Environment="DISCORD_WEBHOOK_URL={webhook_url}"
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

SYSTEMD_TIMER_TEMPLATE = """[Unit]
Description={description}
Requires={service_name}

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=1s

[Install]
WantedBy=timers.target
"""

#############################################################################
# HELPER FUNCTIONS
#############################################################################

def run_ssh(server, command, description=""):
    """Execute command via SSH or locally if on target server"""
    import socket
    current_hostname = socket.gethostname()

    if description:
        print(f"  {description}...", end=" ")

    # If we're on the target server, run locally instead of SSH
    if server == current_hostname:
        result = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True
        )
    else:
        result = subprocess.run(
            ["ssh", server, command],
            capture_output=True,
            text=True
        )

    if description:
        print("✓" if result.returncode == 0 else "✗")

    return result.returncode == 0, result.stdout, result.stderr

def prompt_yes_no(question):
    """Prompt user for yes/no"""
    while True:
        answer = input(f"{question} (y/n): ").lower().strip()
        if answer in ['y', 'yes']:
            return True
        elif answer in ['n', 'no']:
            return False
        print("Please answer 'y' or 'n'")

def select_features_interactive():
    """Interactive feature selection with descriptions"""
    print("\n" + "="*60)
    print("Vast.ai Security Feature Selection")
    print("="*60)

    print("\n🔒 Available Security Features:\n")
    feature_list = [
        ("1", "sudo_restrictions", "Sudo Command Whitelist", "Blocks arbitrary sudo execution"),
        ("2", "discord_monitoring", "Discord Alerts", "Real-time alerts for blocked commands"),
        ("3", "crontab_monitoring", "Crontab Monitoring", "Alerts on crontab modifications"),
        ("4", "core_limits", "Core Dump Limits", "Restricts core file sizes")
    ]

    for num, key, name, desc in feature_list:
        print(f"  [{num}] {name}")
        print(f"      {desc}")

    print("\n💡 Quick Options:")
    print("  [R] Recommended (all security features)")
    print("  [A] All features")
    print("  [C] Custom selection")
    print("  [Q] Quit")

    while True:
        choice = input("\nYour choice: ").strip().upper()

        if choice == 'Q':
            print("Aborted.")
            sys.exit(0)
        elif choice == 'R':
            print("\n✓ Selected: Recommended features")
            return {
                'sudo_restrictions': True,
                'discord_monitoring': True,
                'crontab_monitoring': True,
                'core_limits': True
            }
        elif choice == 'A':
            print("\n✓ Selected: All features")
            return {key: True for key in FEATURES.keys()}
        elif choice == 'C':
            break
        else:
            print("Invalid choice. Please select R, A, C, or Q")

    # Custom selection
    print("\n" + "="*60)
    print("Custom Feature Selection")
    print("="*60 + "\n")

    selected = {}
    for key, desc in FEATURES.items():
        print(f"\n📋 {desc}")
        if 'REBOOT' in desc:
            print("  ⚠️  WARNING: This feature requires a server reboot!")
        selected[key] = prompt_yes_no("  Enable?")

    return selected

#############################################################################
# DEPLOYMENT FUNCTIONS
#############################################################################

def deploy_sudo_restrictions(server, dry_run=False):
    """Deploy restricted sudoers configuration"""
    print("\n📋 Deploying Sudo Restrictions")
    print("-" * 40)

    # Backup
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not dry_run:
        success, _, _ = run_ssh(server,
            f"sudo cp /etc/sudoers /etc/sudoers.backup.{date_str}",
            "Creating backup")
        if not success:
            return False

    # Create restricted file
    sudoers_data = SUDOERS_CONTENT.format(date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    if not dry_run:
        cmd = f"sudo tee /etc/sudoers.d/vastai-restricted > /dev/null << 'EOF'\n{sudoers_data}\nEOF"
        run_ssh(server, cmd, "Creating whitelist")
        run_ssh(server, "sudo chmod 0440 /etc/sudoers.d/vastai-restricted", "Setting permissions")

        # Disable insecure line
        run_ssh(server,
            "sudo sed -i.bak 's/^vastai_kaalia ALL=(ALL) NOPASSWD:ALL/# DISABLED\\n# vastai_kaalia ALL=(ALL) NOPASSWD:ALL/' /etc/sudoers",
            "Disabling insecure sudo")

        success, _, _ = run_ssh(server, "sudo visudo -c", "Validating sudoers")
        if not success:
            print("  ❌ Sudoers validation failed!")
            return False

    print("  ✅ Sudo restrictions deployed\n")
    return True

def deploy_discord_monitoring(server, webhook_url, dry_run=False):
    """Deploy Discord webhook monitoring"""
    print("\n🔔 Deploying Discord Monitoring")
    print("-" * 40)

    if not dry_run:
        # Install script
        cmd = f"sudo tee /usr/local/bin/sudo-monitor.sh > /dev/null << 'EOF'\n{SUDO_MONITOR_SCRIPT}\nEOF"
        run_ssh(server, cmd, "Installing monitor script")
        run_ssh(server, "sudo chmod +x /usr/local/bin/sudo-monitor.sh", "Making executable")

        # Create systemd service
        service_content = SYSTEMD_SERVICE_TEMPLATE.format(
            description="Sudo Denial Monitor",
            script_path="/usr/local/bin/sudo-monitor.sh",
            webhook_url=webhook_url
        )
        cmd = f"sudo tee /etc/systemd/system/sudo-monitor.service > /dev/null << 'EOF'\n{service_content}\nEOF"
        run_ssh(server, cmd, "Creating systemd service")

        # Create timer
        timer_content = SYSTEMD_TIMER_TEMPLATE.format(
            description="Run Sudo Monitor every minute",
            service_name="sudo-monitor.service"
        )
        cmd = f"sudo tee /etc/systemd/system/sudo-monitor.timer > /dev/null << 'EOF'\n{timer_content}\nEOF"
        run_ssh(server, cmd, "Creating systemd timer")

        # Enable and start
        run_ssh(server, "sudo systemctl daemon-reload", "Reloading systemd")
        run_ssh(server, "sudo systemctl enable sudo-monitor.timer", "Enabling timer")
        run_ssh(server, "sudo systemctl start sudo-monitor.timer", "Starting timer")

    print("  ✅ Discord monitoring deployed\n")
    return True

def deploy_crontab_monitoring(server, webhook_url, dry_run=False):
    """Deploy crontab change monitoring"""
    print("\n📅 Deploying Crontab Monitoring")
    print("-" * 40)

    if not dry_run:
        # Install script
        cmd = f"sudo tee /usr/local/bin/crontab-monitor.sh > /dev/null << 'EOF'\n{CRONTAB_MONITOR_SCRIPT}\nEOF"
        run_ssh(server, cmd, "Installing crontab monitor")
        run_ssh(server, "sudo chmod +x /usr/local/bin/crontab-monitor.sh", "Making executable")

        # Create service
        service_content = SYSTEMD_SERVICE_TEMPLATE.format(
            description="Crontab Change Monitor",
            script_path="/usr/local/bin/crontab-monitor.sh",
            webhook_url=webhook_url
        )
        cmd = f"sudo tee /etc/systemd/system/crontab-monitor.service > /dev/null << 'EOF'\n{service_content}\nEOF"
        run_ssh(server, cmd, "Creating systemd service")

        # Create timer
        timer_content = SYSTEMD_TIMER_TEMPLATE.format(
            description="Run Crontab Monitor every minute",
            service_name="crontab-monitor.service"
        )
        cmd = f"sudo tee /etc/systemd/system/crontab-monitor.timer > /dev/null << 'EOF'\n{timer_content}\nEOF"
        run_ssh(server, cmd, "Creating systemd timer")

        # Enable and start
        run_ssh(server, "sudo systemctl daemon-reload", "Reloading systemd")
        run_ssh(server, "sudo systemctl enable crontab-monitor.timer", "Enabling timer")
        run_ssh(server, "sudo systemctl start crontab-monitor.timer", "Starting timer")

        # Initialize hash
        run_ssh(server, "sudo /usr/local/bin/crontab-monitor.sh", "Initializing hash")

    print("  ✅ Crontab monitoring deployed\n")
    return True

def deploy_core_limits(server, dry_run=False):
    """Deploy core dump restrictions"""
    print("\n💾 Deploying Core Dump Limits")
    print("-" * 40)

    if not dry_run:
        # Set core pattern
        run_ssh(server,
            "sudo sysctl -w kernel.core_pattern=/var/lib/vastai_kaalia/data/core-%e.%p.%h.%t",
            "Setting core pattern")

        # Add to sysctl.conf for persistence
        cmd = "grep -q 'kernel.core_pattern' /etc/sysctl.conf || echo 'kernel.core_pattern=/var/lib/vastai_kaalia/data/core-%e.%p.%h.%t' | sudo tee -a /etc/sysctl.conf"
        run_ssh(server, cmd, "Making persistent")

        # Set limits
        limits = "vastai_kaalia - core 2097152"
        cmd = f"grep -q 'vastai_kaalia.*core' /etc/security/limits.conf || echo '{limits}' | sudo tee -a /etc/security/limits.conf"
        run_ssh(server, cmd, "Setting core limits")

    print("  ✅ Core limits deployed\n")
    return True

#############################################################################
# MAIN DEPLOYMENT
#############################################################################

def deploy_to_server(server, webhook_url, features, dry_run=False):
    """Deploy selected features to server"""
    print(f"\n{'='*60}")
    print(f"Deploying to: {server}")
    print(f"{'='*60}")

    if dry_run:
        print("\n🔍 DRY RUN MODE - No changes will be made\n")

    print("\nSelected Features:")
    for key, enabled in features.items():
        status = "✓" if enabled else "✗"
        print(f"  {status} {FEATURES[key]}")
    print()

    results = {}

    if features.get('sudo_restrictions'):
        results['sudo_restrictions'] = deploy_sudo_restrictions(server, dry_run)

    if features.get('discord_monitoring'):
        results['discord_monitoring'] = deploy_discord_monitoring(server, webhook_url, dry_run)

    if features.get('crontab_monitoring'):
        results['crontab_monitoring'] = deploy_crontab_monitoring(server, webhook_url, dry_run)

    if features.get('core_limits'):
        results['core_limits'] = deploy_core_limits(server, dry_run)

    # Test if sudo restrictions were deployed
    if features.get('sudo_restrictions') and not dry_run:
        print("\n🧪 Testing Deployment")
        print("-" * 40)

        # Test allowed command
        success, _, _ = run_ssh(server,
            "sudo -u vastai_kaalia sudo nvidia-smi -pm 1 2>&1",
            "Testing allowed command")

        # Test blocked command (use -n for non-interactive)
        success, output, stderr = run_ssh(server,
            "sudo -u vastai_kaalia sudo -n whoami 2>&1",
            "Testing blocked command")

        if "password is required" in output or "command not allowed" in output or "a password is required" in output:
            print("  ✅ Command blocking works!\n")
        else:
            print("  ⚠️  Warning: Commands may not be properly blocked\n")

    print(f"\n{'='*60}")
    all_success = all(results.values())
    if all_success:
        print(f"✅ Deployment to {server} completed successfully!")
    else:
        print(f"⚠️  Deployment to {server} completed with warnings")
    print(f"{'='*60}\n")

    return all_success

#############################################################################
# UNINSTALL
#############################################################################

def uninstall_from_server(server, restore_permissive=False):
    """Remove all security hardening from server"""
    print(f"\n{'='*60}")
    print(f"Uninstalling from: {server}")
    print(f"{'='*60}\n")

    print("🗑️  Removing Security Hardening")
    print("-" * 40)

    # Stop and disable services
    run_ssh(server, "sudo systemctl stop sudo-monitor.timer 2>/dev/null || true",
            "Stopping sudo-monitor timer")
    run_ssh(server, "sudo systemctl stop sudo-monitor.service 2>/dev/null || true",
            "Stopping sudo-monitor service")
    run_ssh(server, "sudo systemctl stop crontab-monitor.service 2>/dev/null || true",
            "Stopping crontab-monitor service")

    run_ssh(server, "sudo systemctl disable sudo-monitor.timer 2>/dev/null || true",
            "Disabling sudo-monitor timer")
    run_ssh(server, "sudo systemctl disable sudo-monitor.service 2>/dev/null || true",
            "Disabling sudo-monitor service")
    run_ssh(server, "sudo systemctl disable crontab-monitor.service 2>/dev/null || true",
            "Disabling crontab-monitor service")

    # Remove systemd files
    run_ssh(server, "sudo rm -f /etc/systemd/system/sudo-monitor.service",
            "Removing sudo-monitor.service")
    run_ssh(server, "sudo rm -f /etc/systemd/system/sudo-monitor.timer",
            "Removing sudo-monitor.timer")
    run_ssh(server, "sudo rm -f /etc/systemd/system/crontab-monitor.service",
            "Removing crontab-monitor.service")

    # Remove override directories
    run_ssh(server, "sudo rm -rf /etc/systemd/system/sudo-monitor.service.d",
            "Removing service overrides")
    run_ssh(server, "sudo rm -rf /etc/systemd/system/crontab-monitor.service.d",
            "Removing service overrides")

    # Remove monitoring scripts
    run_ssh(server, "sudo rm -f /usr/local/bin/sudo-monitor.sh",
            "Removing sudo-monitor.sh")
    run_ssh(server, "sudo rm -f /usr/local/bin/sudo-monitor.py",
            "Removing sudo-monitor.py")
    run_ssh(server, "sudo rm -f /usr/local/bin/crontab-monitor.sh",
            "Removing crontab-monitor.sh")

    # Handle sudoers restoration
    if restore_permissive:
        print("\n⚠️  Restoring permissive sudo access")
        # Look for backup
        success, output, _ = run_ssh(server,
            "ls -1t /etc/sudoers.backup.* 2>/dev/null | head -1",
            "Finding sudoers backup")

        if success and output.strip():
            backup_file = output.strip()
            run_ssh(server, f"sudo cp {backup_file} /etc/sudoers.d/vastai-permissive",
                    "Restoring from backup")
            print(f"  ℹ️  Restored from: {backup_file}")
        else:
            # Create permissive sudoers
            permissive = "vastai_kaalia ALL=(ALL) NOPASSWD:ALL"
            run_ssh(server, f"echo '{permissive}' | sudo tee /etc/sudoers.d/vastai-permissive > /dev/null",
                    "Creating permissive sudoers")
            print("  ℹ️  No backup found, created new permissive rule")

    # Remove restricted sudoers
    run_ssh(server, "sudo rm -f /etc/sudoers.d/vastai-restricted",
            "Removing restricted sudoers")

    # Validate sudoers syntax
    success, output, stderr = run_ssh(server, "sudo visudo -c", "Validating sudoers syntax")
    if not success:
        print(f"  ⚠️  Warning: sudoers syntax check failed: {stderr}")

    # Reload systemd
    run_ssh(server, "sudo systemctl daemon-reload", "Reloading systemd")

    # Reset failed units
    run_ssh(server, "sudo systemctl reset-failed 2>/dev/null || true",
            "Resetting failed units")

    print("\n✅ Uninstall complete")
    print(f"{'='*60}\n")

    return True

#############################################################################
# MAIN
#############################################################################

def main():
    parser = argparse.ArgumentParser(
        description="Deploy Vast.ai security hardening (modular)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--servers", help="Server(s) to deploy to (single or comma-separated list)")
    parser.add_argument("--webhook", help="Discord webhook URL")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done")

    # Uninstall mode
    parser.add_argument("--uninstall", action="store_true", help="Remove all security hardening")
    parser.add_argument("--restore-permissive", action="store_true",
                        help="Restore permissive sudo access when uninstalling (use with --uninstall)")

    # Feature flags
    parser.add_argument("--all", action="store_true", help="Deploy all features")
    parser.add_argument("--interactive", action="store_true", help="Interactive feature selection")
    parser.add_argument("--sudo-restrictions", action="store_true", help="Deploy sudo restrictions")
    parser.add_argument("--discord-monitoring", action="store_true", help="Deploy Discord monitoring")
    parser.add_argument("--crontab-monitoring", action="store_true", help="Deploy crontab monitoring")
    parser.add_argument("--core-limits", action="store_true", help="Deploy core dump limits")

    args = parser.parse_args()

    # Default to current server if not specified
    if not args.servers:
        import socket
        current_server = socket.gethostname()
        args.servers = current_server
        if args.uninstall:
            print("\n" + "="*60)
            print("Vast.ai Security Hardening Uninstall")
            print("="*60)
            print(f"\nℹ️  Uninstalling from current server: {current_server}")
            print("    (use --servers to uninstall from different servers)\n")
        else:
            print("\n" + "="*60)
            print("Vast.ai Security Hardening Deployment")
            print("="*60)
            print(f"\nℹ️  Deploying to current server: {current_server}")
            print("    (use --servers to deploy to different servers)\n")

    # Handle uninstall mode
    if args.uninstall:
        servers = [s.strip() for s in args.servers.split(",")]

        print("\n" + "="*60)
        print("Vast.ai Security Hardening Uninstall")
        print("="*60)
        print(f"\nServers: {', '.join(servers)}")
        print(f"Restore permissive sudo: {args.restore_permissive}")

        if args.restore_permissive:
            print("\n⚠️  WARNING: This will restore permissive sudo access!")
            print("    vastai_kaalia will have full root access again.\n")

        # Uninstall from each server
        results = {}
        for server in servers:
            try:
                success = uninstall_from_server(server, args.restore_permissive)
                results[server] = "✅ SUCCESS" if success else "⚠️  WARNING"
            except Exception as e:
                print(f"\n❌ Error uninstalling from {server}: {e}")
                results[server] = "❌ ERROR"

        # Summary
        print("\n" + "="*60)
        print("Uninstall Summary")
        print("="*60)
        for server, status in results.items():
            print(f"{status} {server}")
        print()
        return

    # Prompt for webhook if not provided (only for install mode)
    if not args.webhook:
        args.webhook = input("Enter Discord webhook URL: ").strip()
        if not args.webhook:
            print("Error: No webhook URL specified")
            sys.exit(1)

    # Determine servers (handles both single and comma-separated)
    servers = [s.strip() for s in args.servers.split(",")]

    # Determine features - auto-interactive if nothing specified
    feature_flags_provided = any([
        args.all, args.interactive, args.sudo_restrictions,
        args.discord_monitoring, args.crontab_monitoring, args.core_limits
    ])

    if not feature_flags_provided:
        # No flags provided - go into interactive mode
        features = select_features_interactive()
    elif args.interactive:
        features = select_features_interactive()
    elif args.all:
        features = {key: True for key in FEATURES.keys()}
    else:
        features = {
            'sudo_restrictions': args.sudo_restrictions,
            'discord_monitoring': args.discord_monitoring,
            'crontab_monitoring': args.crontab_monitoring,
            'core_limits': args.core_limits
        }

        if not any(features.values()):
            print("Error: No features selected. Use --all, --interactive, or specify individual features")
            sys.exit(1)

    print("\n" + "="*60)
    print("Vast.ai Security Hardening Deployment")
    print("="*60)
    print(f"\nServers: {', '.join(servers)}")
    print(f"Discord webhook: {args.webhook[:50]}...")
    print(f"Dry run: {args.dry_run}")

    # Deploy to each server
    results = {}
    for server in servers:
        try:
            success = deploy_to_server(server, args.webhook, features, args.dry_run)
            results[server] = "✅ SUCCESS" if success else "⚠️  WARNING"
        except Exception as e:
            print(f"\n❌ Error deploying to {server}: {e}")
            results[server] = "❌ ERROR"

    # Summary
    print("\n" + "="*60)
    print("Deployment Summary")
    print("="*60)
    for server, status in results.items():
        print(f"{status} {server}")
    print()

if __name__ == "__main__":
    main()
