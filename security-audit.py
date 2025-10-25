#!/usr/bin/env python3
"""
Vast.ai Host Security Audit Script
Performs comprehensive security checks on Ubuntu servers hosting on vast.ai
without interfering with vast.ai operations.
"""

import subprocess
import os
import pwd
import grp
import stat
import json
import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import sys

# ANSI color codes
class Colors:
    CRITICAL = '\033[91m'  # Red
    HIGH = '\033[93m'      # Yellow
    MEDIUM = '\033[94m'    # Blue
    LOW = '\033[92m'       # Green
    INFO = '\033[96m'      # Cyan
    RESET = '\033[0m'
    BOLD = '\033[1m'

class SecurityCheck:
    def __init__(self, category: str, name: str, severity: str, status: str,
                 description: str, details: str = "", remediation: str = ""):
        self.category = category
        self.name = name
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO, PASS
        self.status = status      # FAIL, WARN, PASS, INFO
        self.description = description
        self.details = details
        self.remediation = remediation
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            'category': self.category,
            'name': self.name,
            'severity': self.severity,
            'status': self.status,
            'description': self.description,
            'details': self.details,
            'remediation': self.remediation,
            'timestamp': self.timestamp
        }

class SecurityAuditor:
    def __init__(self, verbose=False, json_output=False):
        self.verbose = verbose
        self.json_output = json_output
        self.results: List[SecurityCheck] = []

    def run_command(self, cmd: List[str], check=False) -> Tuple[int, str, str]:
        """Run command and return (returncode, stdout, stderr)"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return 1, "", "Command timeout"
        except Exception as e:
            return 1, "", str(e)

    def add_result(self, check: SecurityCheck):
        """Add check result to results list"""
        self.results.append(check)

    # ============================================
    # SSH SECURITY CHECKS
    # ============================================

    def check_ssh_port(self):
        """Check if SSH is running on default port 22"""
        rc, stdout, _ = self.run_command(['grep', '-E', '^Port', '/etc/ssh/sshd_config'])

        if rc != 0:
            # No Port directive = default port 22
            self.add_result(SecurityCheck(
                'SSH', 'SSH Default Port', 'MEDIUM', 'WARN',
                'SSH is using default port 22',
                'Default port 22 is commonly targeted by automated attacks',
                'Change SSH port in /etc/ssh/sshd_config (e.g., Port 2222) and restart sshd'
            ))
        else:
            port = stdout.strip().split()[-1]
            if port == '22':
                self.add_result(SecurityCheck(
                    'SSH', 'SSH Default Port', 'MEDIUM', 'WARN',
                    'SSH is using default port 22',
                    f'Port configured: {port}',
                    'Change SSH port to non-standard port (1024-65535)'
                ))
            else:
                self.add_result(SecurityCheck(
                    'SSH', 'SSH Default Port', 'INFO', 'PASS',
                    'SSH using non-default port',
                    f'Port configured: {port}',
                    ''
                ))

    def check_ssh_password_auth(self):
        """Check if password authentication is enabled"""
        rc, stdout, _ = self.run_command(['grep', '-E', '^PasswordAuthentication', '/etc/ssh/sshd_config'])

        if rc != 0 or 'yes' in stdout.lower():
            self.add_result(SecurityCheck(
                'SSH', 'Password Authentication', 'HIGH', 'FAIL',
                'SSH password authentication is enabled',
                'Password authentication allows brute-force attacks',
                'Set "PasswordAuthentication no" in /etc/ssh/sshd_config and restart sshd'
            ))
        else:
            self.add_result(SecurityCheck(
                'SSH', 'Password Authentication', 'INFO', 'PASS',
                'SSH password authentication disabled',
                'Using key-based authentication',
                ''
            ))

    def check_ssh_root_login(self):
        """Check if root login is permitted"""
        rc, stdout, _ = self.run_command(['grep', '-E', '^PermitRootLogin', '/etc/ssh/sshd_config'])

        if rc != 0:
            self.add_result(SecurityCheck(
                'SSH', 'Root Login', 'HIGH', 'WARN',
                'PermitRootLogin not explicitly set (defaults to yes)',
                'Root login should be disabled',
                'Set "PermitRootLogin no" in /etc/ssh/sshd_config'
            ))
        elif 'yes' in stdout.lower():
            self.add_result(SecurityCheck(
                'SSH', 'Root Login', 'HIGH', 'FAIL',
                'Root login via SSH is permitted',
                stdout.strip(),
                'Set "PermitRootLogin no" or "PermitRootLogin prohibit-password"'
            ))
        else:
            self.add_result(SecurityCheck(
                'SSH', 'Root Login', 'INFO', 'PASS',
                'Root login disabled or restricted',
                stdout.strip(),
                ''
            ))

    def check_ssh_empty_passwords(self):
        """Check if empty passwords are permitted"""
        rc, stdout, _ = self.run_command(['grep', '-E', '^PermitEmptyPasswords', '/etc/ssh/sshd_config'])

        if 'yes' in stdout.lower():
            self.add_result(SecurityCheck(
                'SSH', 'Empty Passwords', 'CRITICAL', 'FAIL',
                'Empty passwords are permitted',
                'Allows login with no password',
                'Set "PermitEmptyPasswords no" in /etc/ssh/sshd_config'
            ))
        else:
            self.add_result(SecurityCheck(
                'SSH', 'Empty Passwords', 'INFO', 'PASS',
                'Empty passwords not permitted',
                'Default behavior maintained',
                ''
            ))

    def check_ssh_max_auth_tries(self):
        """Check MaxAuthTries configuration"""
        rc, stdout, _ = self.run_command(['grep', '-E', '^MaxAuthTries', '/etc/ssh/sshd_config'])

        if rc == 0:
            tries = int(stdout.strip().split()[-1])
            if tries > 6:
                self.add_result(SecurityCheck(
                    'SSH', 'Max Auth Tries', 'LOW', 'WARN',
                    f'MaxAuthTries is set to {tries}',
                    'Higher values allow more brute-force attempts',
                    'Set MaxAuthTries to 3-4 in /etc/ssh/sshd_config'
                ))
            else:
                self.add_result(SecurityCheck(
                    'SSH', 'Max Auth Tries', 'INFO', 'PASS',
                    f'MaxAuthTries configured appropriately ({tries})',
                    '',
                    ''
                ))

    # ============================================
    # FIREWALL & NETWORK CHECKS
    # ============================================

    def check_ufw_status(self):
        """Check UFW firewall status"""
        rc, stdout, _ = self.run_command(['ufw', 'status'])

        if 'inactive' in stdout.lower():
            self.add_result(SecurityCheck(
                'Firewall', 'UFW Status', 'HIGH', 'FAIL',
                'UFW firewall is inactive',
                'No firewall protection enabled',
                'Enable UFW with: sudo ufw enable'
            ))
        elif 'active' in stdout.lower():
            self.add_result(SecurityCheck(
                'Firewall', 'UFW Status', 'INFO', 'PASS',
                'UFW firewall is active',
                stdout.strip()[:200],
                ''
            ))
        else:
            self.add_result(SecurityCheck(
                'Firewall', 'UFW Status', 'MEDIUM', 'WARN',
                'UFW not installed or not responding',
                'Consider installing: apt install ufw',
                'Install and configure UFW firewall'
            ))

    def check_open_ports(self):
        """Check for open listening ports"""
        rc, stdout, _ = self.run_command(['ss', '-tuln'])

        if rc == 0:
            lines = stdout.strip().split('\n')[1:]  # Skip header
            open_ports = []
            risky_ports = []

            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    local_addr = parts[4]
                    if ':' in local_addr:
                        port = local_addr.split(':')[-1]
                        # Check for 0.0.0.0 or :: (listening on all interfaces)
                        if '0.0.0.0:' in local_addr or ':::' in local_addr:
                            open_ports.append(f'{parts[0]} {local_addr}')

                            # Flag potentially risky services
                            if port in ['21', '23', '25', '110', '143', '3306', '5432', '6379', '27017']:
                                risky_ports.append(f'{parts[0]} port {port}')

            if risky_ports:
                self.add_result(SecurityCheck(
                    'Network', 'Risky Open Ports', 'HIGH', 'WARN',
                    f'Found {len(risky_ports)} potentially risky services exposed',
                    '\n'.join(risky_ports[:10]),
                    'Review if these services need to be publicly accessible'
                ))

            if len(open_ports) > 10:
                self.add_result(SecurityCheck(
                    'Network', 'Open Ports', 'MEDIUM', 'WARN',
                    f'Found {len(open_ports)} services listening on all interfaces',
                    '\n'.join(open_ports[:15]) + f'\n... and {len(open_ports)-15} more',
                    'Review open ports and close unnecessary services'
                ))

    # ============================================
    # USER & ACCESS CONTROL CHECKS
    # ============================================

    def check_users_with_empty_passwords(self):
        """Check for users with empty passwords"""
        rc, stdout, _ = self.run_command(['sudo', 'awk', '-F:', '($2 == "") {print $1}', '/etc/shadow'])

        if stdout.strip():
            users = stdout.strip().split('\n')
            self.add_result(SecurityCheck(
                'Users', 'Empty Passwords', 'CRITICAL', 'FAIL',
                f'Found {len(users)} user(s) with empty passwords',
                ', '.join(users),
                'Lock or set passwords for these accounts'
            ))

    def check_uid_zero_accounts(self):
        """Check for accounts with UID 0 (root privileges)"""
        uid_zero = []
        for user in pwd.getpwall():
            if user.pw_uid == 0 and user.pw_name != 'root':
                uid_zero.append(user.pw_name)

        if uid_zero:
            self.add_result(SecurityCheck(
                'Users', 'UID 0 Accounts', 'CRITICAL', 'FAIL',
                f'Found {len(uid_zero)} non-root account(s) with UID 0',
                ', '.join(uid_zero),
                'Remove or change UID for these accounts - only root should have UID 0'
            ))

    def check_sudo_nopasswd(self):
        """Check for NOPASSWD sudo entries (excluding vastai_kaalia)"""
        rc, stdout, _ = self.run_command(['sudo', 'grep', '-r', 'NOPASSWD', '/etc/sudoers', '/etc/sudoers.d/'])

        if stdout:
            lines = [l for l in stdout.strip().split('\n') if 'vastai_kaalia' not in l and not l.strip().startswith('#')]
            if lines:
                self.add_result(SecurityCheck(
                    'Users', 'NOPASSWD Sudo', 'MEDIUM', 'WARN',
                    f'Found {len(lines)} NOPASSWD sudo configuration(s)',
                    '\n'.join(lines[:10]),
                    'Review if password-less sudo is necessary'
                ))

    def check_authorized_keys_permissions(self):
        """Check permissions on .ssh/authorized_keys files"""
        issues = []
        for user in pwd.getpwall():
            auth_keys = Path(user.pw_dir) / '.ssh' / 'authorized_keys'
            if auth_keys.exists():
                st = auth_keys.stat()
                mode = stat.filemode(st.st_mode)

                # Check if world or group writable
                if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    issues.append(f'{auth_keys}: {mode} (writable by others)')

                # Check ownership
                if st.st_uid != user.pw_uid:
                    issues.append(f'{auth_keys}: owned by UID {st.st_uid}, should be {user.pw_uid}')

        if issues:
            self.add_result(SecurityCheck(
                'Users', 'SSH Keys Permissions', 'HIGH', 'FAIL',
                f'Found {len(issues)} authorized_keys file(s) with incorrect permissions',
                '\n'.join(issues[:10]),
                'Fix with: chmod 600 ~/.ssh/authorized_keys && chown $USER ~/.ssh/authorized_keys'
            ))

    # ============================================
    # SYSTEM UPDATES & PACKAGES
    # ============================================

    def check_pending_updates(self):
        """Check for pending security updates"""
        # Update apt cache first
        subprocess.run(['sudo', 'apt-get', 'update'], capture_output=True, timeout=60)

        rc, stdout, _ = self.run_command(['apt', 'list', '--upgradable'])

        if rc == 0 and stdout:
            upgradable = len(stdout.strip().split('\n')) - 1  # Subtract header

            # Check for security updates
            rc2, stdout2, _ = self.run_command(['apt', 'list', '--upgradable', '2>/dev/null'])
            security_updates = len([l for l in stdout2.split('\n') if 'security' in l.lower()])

            if security_updates > 0:
                self.add_result(SecurityCheck(
                    'Updates', 'Security Updates', 'HIGH', 'WARN',
                    f'{security_updates} security update(s) available',
                    f'Total upgradable packages: {upgradable}',
                    'Run: sudo apt update && sudo apt upgrade'
                ))
            elif upgradable > 20:
                self.add_result(SecurityCheck(
                    'Updates', 'Pending Updates', 'MEDIUM', 'WARN',
                    f'{upgradable} package(s) can be upgraded',
                    'System may be outdated',
                    'Run: sudo apt update && sudo apt upgrade'
                ))

    def check_unattended_upgrades(self):
        """Check if unattended-upgrades is configured"""
        if not Path('/etc/apt/apt.conf.d/50unattended-upgrades').exists():
            self.add_result(SecurityCheck(
                'Updates', 'Unattended Upgrades', 'MEDIUM', 'WARN',
                'Unattended-upgrades not configured',
                'Automatic security updates not enabled',
                'Install with: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades'
            ))
        else:
            # Check if it's enabled
            rc, stdout, _ = self.run_command(['systemctl', 'is-enabled', 'unattended-upgrades'])
            if 'enabled' in stdout:
                self.add_result(SecurityCheck(
                    'Updates', 'Unattended Upgrades', 'INFO', 'PASS',
                    'Automatic security updates enabled',
                    '',
                    ''
                ))

    # ============================================
    # FILE SYSTEM SECURITY CHECKS
    # ============================================

    def check_world_writable_files(self):
        """Check for world-writable files in critical locations"""
        rc, stdout, _ = self.run_command([
            'find', '/etc', '/usr/bin', '/usr/sbin', '/usr/local/bin',
            '-type', 'f', '-perm', '-002', '!', '-path', '*/proc/*',
            '2>/dev/null'
        ])

        if stdout.strip():
            files = stdout.strip().split('\n')
            if len(files) > 0:
                self.add_result(SecurityCheck(
                    'FileSystem', 'World-Writable Files', 'HIGH', 'FAIL',
                    f'Found {len(files)} world-writable file(s) in system directories',
                    '\n'.join(files[:10]),
                    'Remove world-write permissions: chmod o-w <file>'
                ))

    def check_suid_binaries(self):
        """Check for unusual SUID binaries"""
        rc, stdout, _ = self.run_command([
            'find', '/', '-type', 'f', '-perm', '-4000',
            '!', '-path', '/proc/*', '!', '-path', '/sys/*',
            '2>/dev/null'
        ])

        if stdout.strip():
            binaries = stdout.strip().split('\n')

            # Common safe SUID binaries
            safe_suid = {'/usr/bin/sudo', '/usr/bin/su', '/usr/bin/passwd', '/usr/bin/chsh',
                        '/usr/bin/chfn', '/usr/bin/newgrp', '/usr/bin/gpasswd',
                        '/usr/bin/mount', '/usr/bin/umount', '/usr/bin/ping',
                        '/usr/lib/openssh/ssh-keysign', '/usr/lib/dbus-1.0/dbus-daemon-launch-helper'}

            unusual = [b for b in binaries if b not in safe_suid]

            if len(unusual) > 5:
                self.add_result(SecurityCheck(
                    'FileSystem', 'SUID Binaries', 'MEDIUM', 'WARN',
                    f'Found {len(unusual)} SUID binaries beyond common system tools',
                    '\n'.join(unusual[:15]),
                    'Review if SUID bit is necessary for these binaries'
                ))

    # ============================================
    # LOGGING & AUDITING
    # ============================================

    def check_failed_login_attempts(self):
        """Check for excessive failed login attempts"""
        rc, stdout, _ = self.run_command(['grep', '-c', 'Failed password', '/var/log/auth.log'])

        if rc == 0 and stdout.strip().isdigit():
            failed_count = int(stdout.strip())
            if failed_count > 100:
                self.add_result(SecurityCheck(
                    'Logging', 'Failed Logins', 'HIGH', 'WARN',
                    f'{failed_count} failed password attempts in auth.log',
                    'High number of failed login attempts detected',
                    'Review /var/log/auth.log and consider implementing fail2ban'
                ))
            elif failed_count > 10:
                self.add_result(SecurityCheck(
                    'Logging', 'Failed Logins', 'MEDIUM', 'INFO',
                    f'{failed_count} failed password attempts in auth.log',
                    'Some failed login attempts detected',
                    'Monitor /var/log/auth.log regularly'
                ))

    def check_auditd(self):
        """Check if auditd is installed and running"""
        rc, _, _ = self.run_command(['which', 'auditd'])

        if rc != 0:
            self.add_result(SecurityCheck(
                'Logging', 'Audit Daemon', 'LOW', 'INFO',
                'Auditd not installed',
                'System activity auditing not enabled',
                'Consider installing auditd for comprehensive security auditing'
            ))
        else:
            rc, stdout, _ = self.run_command(['systemctl', 'is-active', 'auditd'])
            if 'active' not in stdout:
                self.add_result(SecurityCheck(
                    'Logging', 'Audit Daemon', 'MEDIUM', 'WARN',
                    'Auditd installed but not running',
                    '',
                    'Start auditd: sudo systemctl start auditd'
                ))

    # ============================================
    # SYSTEM HARDENING
    # ============================================

    def check_fail2ban(self):
        """Check fail2ban intrusion prevention"""
        rc, stdout, _ = self.run_command(['systemctl', 'is-active', 'fail2ban'])

        if rc != 0:  # Not active
            rc2, _, _ = self.run_command(['which', 'fail2ban-server'])
            if rc2 != 0:
                self.add_result(SecurityCheck(
                    'Hardening', 'fail2ban', 'HIGH', 'FAIL',
                    'fail2ban not installed',
                    'Intrusion prevention system missing',
                    'Install with: sudo apt install fail2ban && sudo systemctl enable --now fail2ban'
                ))
            else:
                self.add_result(SecurityCheck(
                    'Hardening', 'fail2ban Service', 'HIGH', 'WARN',
                    'fail2ban installed but not active',
                    'Service is not running',
                    'Start with: sudo systemctl enable --now fail2ban'
                ))
        else:
            # Check if SSH jail is enabled
            rc3, jails, _ = self.run_command(['fail2ban-client', 'status'])
            if 'sshd' in jails or 'ssh' in jails:
                self.add_result(SecurityCheck(
                    'Hardening', 'fail2ban', 'INFO', 'PASS',
                    'fail2ban active with SSH protection',
                    'SSH jail is configured',
                    ''
                ))
            else:
                self.add_result(SecurityCheck(
                    'Hardening', 'fail2ban SSH Jail', 'MEDIUM', 'WARN',
                    'fail2ban active but SSH jail not detected',
                    'SSH may not be protected',
                    'Configure SSH jail in /etc/fail2ban/jail.local'
                ))

    def check_apparmor_selinux(self):
        """Check AppArmor or SELinux status"""
        # Check AppArmor first (more common on Ubuntu)
        rc, stdout, _ = self.run_command(['aa-status'], check=False)
        if rc == 0 and 'profiles are loaded' in stdout:
            profiles = stdout.split('\n')[0]
            self.add_result(SecurityCheck(
                'Hardening', 'AppArmor', 'INFO', 'PASS',
                'AppArmor is active',
                profiles,
                ''
            ))
            return

        # Check SELinux
        rc, stdout, _ = self.run_command(['getenforce'], check=False)
        if rc == 0:
            status = stdout.strip()
            if status == 'Enforcing':
                self.add_result(SecurityCheck(
                    'Hardening', 'SELinux', 'INFO', 'PASS',
                    'SELinux is enforcing',
                    'Mandatory Access Control active',
                    ''
                ))
            else:
                self.add_result(SecurityCheck(
                    'Hardening', 'SELinux', 'LOW', 'WARN',
                    f'SELinux is {status.lower()}',
                    'MAC not enforcing policies',
                    'Consider setting to enforcing mode'
                ))
            return

        # Neither found
        self.add_result(SecurityCheck(
            'Hardening', 'MAC System', 'LOW', 'WARN',
            'No Mandatory Access Control system detected',
            'Neither AppArmor nor SELinux found',
            'Consider enabling AppArmor (recommended for Ubuntu)'
        ))

    def check_ip_forwarding(self):
        """Check if IP forwarding is enabled"""
        ipv4_path = Path('/proc/sys/net/ipv4/ip_forward')
        if ipv4_path.exists():
            value = ipv4_path.read_text().strip()
            if value == '1':
                # This is likely needed for Docker/vast.ai, so just INFO
                self.add_result(SecurityCheck(
                    'Hardening', 'IP Forwarding', 'INFO', 'INFO',
                    'IP forwarding is enabled',
                    'Required for Docker networking on vast.ai',
                    ''
                ))

    def check_core_dumps(self):
        """Check core dump configuration"""
        limits_path = Path('/etc/security/limits.conf')
        if limits_path.exists():
            content = limits_path.read_text()
            if '* hard core 0' in content or '* soft core 0' in content:
                self.add_result(SecurityCheck(
                    'Hardening', 'Core Dumps', 'INFO', 'PASS',
                    'Core dumps are disabled',
                    'Prevents sensitive data exposure',
                    ''
                ))
            else:
                self.add_result(SecurityCheck(
                    'Hardening', 'Core Dumps', 'LOW', 'WARN',
                    'Core dumps may be enabled',
                    'Could expose sensitive information',
                    'Disable by adding "* hard core 0" to /etc/security/limits.conf'
                ))

    def check_password_aging(self):
        """Check password aging policies"""
        login_defs = Path('/etc/login.defs')
        if login_defs.exists():
            content = login_defs.read_text()
            issues = []

            # Check PASS_MAX_DAYS
            max_days = None
            for line in content.split('\n'):
                if line.strip().startswith('PASS_MAX_DAYS') and not line.strip().startswith('#'):
                    try:
                        max_days = int(line.split()[1])
                        break
                    except (IndexError, ValueError):
                        pass

            if max_days is None or max_days > 90:
                issues.append(f'PASS_MAX_DAYS={max_days or "not set"} (recommend ≤90)')

            if issues:
                self.add_result(SecurityCheck(
                    'Hardening', 'Password Aging', 'LOW', 'WARN',
                    'Weak password aging policy',
                    '; '.join(issues),
                    'Edit /etc/login.defs to set PASS_MAX_DAYS 90'
                ))

    # ============================================
    # DOCKER SECURITY (vast.ai specific)
    # ============================================

    def check_docker_socket_permissions(self):
        """Check Docker socket permissions"""
        socket_path = Path('/var/run/docker.sock')
        if socket_path.exists():
            st = socket_path.stat()
            mode = stat.filemode(st.st_mode)

            if st.st_mode & stat.S_IWOTH:
                self.add_result(SecurityCheck(
                    'Docker', 'Socket Permissions', 'CRITICAL', 'FAIL',
                    'Docker socket is world-writable',
                    f'Current permissions: {mode}',
                    'Fix with: sudo chmod 660 /var/run/docker.sock'
                ))

    def check_docker_group_membership(self):
        """Check for non-vast users in docker group"""
        try:
            docker_group = grp.getgrnam('docker')
            members = [m for m in docker_group.gr_mem if m not in ['vastai_kaalia', 'root']]

            if members:
                self.add_result(SecurityCheck(
                    'Docker', 'Group Membership', 'MEDIUM', 'WARN',
                    f'{len(members)} user(s) in docker group',
                    ', '.join(members),
                    'Docker group membership grants root-equivalent access'
                ))
        except KeyError:
            pass  # Docker group doesn't exist

    # ============================================
    # MAIN AUDIT RUNNER
    # ============================================

    def run_all_checks(self):
        """Run all security checks"""
        if not self.json_output:
            print(f"\n{Colors.BOLD}Starting Security Audit...{Colors.RESET}\n")

        # SSH Checks
        self.check_ssh_port()
        self.check_ssh_password_auth()
        self.check_ssh_root_login()
        self.check_ssh_empty_passwords()
        self.check_ssh_max_auth_tries()

        # Firewall & Network
        self.check_ufw_status()
        self.check_open_ports()

        # User & Access
        self.check_users_with_empty_passwords()
        self.check_uid_zero_accounts()
        self.check_sudo_nopasswd()
        self.check_authorized_keys_permissions()

        # Updates
        self.check_pending_updates()
        self.check_unattended_upgrades()

        # File System
        self.check_world_writable_files()
        self.check_suid_binaries()

        # Logging
        self.check_failed_login_attempts()
        self.check_auditd()

        # System Hardening
        self.check_fail2ban()
        self.check_apparmor_selinux()
        self.check_ip_forwarding()
        self.check_core_dumps()
        self.check_password_aging()

        # Docker (vast.ai specific)
        self.check_docker_socket_permissions()
        self.check_docker_group_membership()

    def print_results(self):
        """Print results in formatted output"""
        if self.json_output:
            print(json.dumps([r.to_dict() for r in self.results], indent=2))
            return

        # Group by category
        categories = {}
        for result in self.results:
            if result.category not in categories:
                categories[result.category] = []
            categories[result.category].append(result)

        # Print by category
        for category, checks in categories.items():
            print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
            print(f"{Colors.BOLD}{category}{Colors.RESET}")
            print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")

            for check in checks:
                # Choose color based on severity
                if check.severity == 'CRITICAL':
                    color = Colors.CRITICAL
                elif check.severity == 'HIGH':
                    color = Colors.HIGH
                elif check.severity == 'MEDIUM':
                    color = Colors.MEDIUM
                elif check.severity == 'LOW':
                    color = Colors.LOW
                else:
                    color = Colors.INFO

                status_symbol = '✗' if check.status == 'FAIL' else ('⚠' if check.status == 'WARN' else '✓')

                print(f"{color}{status_symbol} [{check.severity}] {check.name}{Colors.RESET}")
                print(f"   {check.description}")

                if self.verbose and check.details:
                    print(f"   Details: {check.details[:200]}")

                if check.remediation:
                    print(f"   {Colors.BOLD}→{Colors.RESET} {check.remediation}")

                print()

        # Print summary
        self.print_summary()

    def print_summary(self):
        """Print summary statistics"""
        critical = sum(1 for r in self.results if r.severity == 'CRITICAL' and r.status == 'FAIL')
        high = sum(1 for r in self.results if r.severity == 'HIGH' and (r.status in ['FAIL', 'WARN']))
        medium = sum(1 for r in self.results if r.severity == 'MEDIUM' and (r.status in ['FAIL', 'WARN']))
        low = sum(1 for r in self.results if r.severity == 'LOW' and (r.status in ['FAIL', 'WARN']))
        passed = sum(1 for r in self.results if r.status == 'PASS')

        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}SUMMARY{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")

        if critical > 0:
            print(f"{Colors.CRITICAL}● Critical Issues: {critical}{Colors.RESET}")
        if high > 0:
            print(f"{Colors.HIGH}● High Priority: {high}{Colors.RESET}")
        if medium > 0:
            print(f"{Colors.MEDIUM}● Medium Priority: {medium}{Colors.RESET}")
        if low > 0:
            print(f"{Colors.LOW}● Low Priority: {low}{Colors.RESET}")
        print(f"{Colors.INFO}● Checks Passed: {passed}{Colors.RESET}")
        print()

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Security audit script for vast.ai Ubuntu hosts',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show detailed information')
    parser.add_argument('-j', '--json', action='store_true',
                       help='Output results as JSON')

    args = parser.parse_args()

    auditor = SecurityAuditor(verbose=args.verbose, json_output=args.json)
    auditor.run_all_checks()
    auditor.print_results()

    # Exit code based on severity
    critical = sum(1 for r in auditor.results if r.severity == 'CRITICAL' and r.status == 'FAIL')
    high = sum(1 for r in auditor.results if r.severity == 'HIGH' and r.status in ['FAIL', 'WARN'])

    if critical > 0:
        sys.exit(2)  # Critical issues found
    elif high > 0:
        sys.exit(1)  # High priority issues found
    else:
        sys.exit(0)  # All clear or only medium/low issues

if __name__ == '__main__':
    main()
