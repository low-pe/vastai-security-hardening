# Vast.ai Complete Sudo Whitelist

All 47 commands that `vastai_kaalia` is permitted to run with sudo privileges.

---

## Docker Container Management

```sudoers
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/cat /var/lib/docker/*
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/du -d 0 -h /var/lib/docker/*
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/du /var/lib/docker/*
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/docker ps *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/docker inspect *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/docker logs *
```

## GPU Management

```sudoers
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/timeout * /usr/bin/nvidia-smi -pm 1
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/timeout * nvidia-smi -pm 1
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/nvidia-smi -pm 1
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/nvidia-smi -pm ENABLED
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/cat /sys/module/nvidia_drm/parameters/modeset
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/cat /sys/*
```

## Network Diagnostics

```sudoers
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/ss *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/tshark *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/apt-get install * tshark
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/apt-get install -yq tshark
```

## SSH Daemon Management

```sudoers
vastai_kaalia ALL=(root) NOPASSWD: /usr/sbin/sshd -p *
```

## System Configuration

```sudoers
vastai_kaalia ALL=(root) NOPASSWD: /usr/sbin/sysctl -w kernel.core_pattern=*
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/sed -i * /etc/security/limits.conf
```

## System Diagnostics

```sudoers
vastai_kaalia ALL=(root) NOPASSWD: /usr/sbin/dmidecode *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/timeout * /usr/bin/journalctl *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/timeout * journalctl *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/journalctl *
vastai_kaalia ALL=(root) NOPASSWD: /bin/journalctl *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/fio *
```

## Vast.ai Updates

```sudoers
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/usermod -a -G docker vastai_kaalia
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/cp -f * /usr/local/bin/vastai-run-update
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/chmod a+x /usr/local/bin/vastai-run-update
vastai_kaalia ALL=(root) NOPASSWD: /usr/sbin/logrotate *
```

## Iptables Management

```sudoers
vastai_kaalia ALL=(root) NOPASSWD: /usr/sbin/iptables *
vastai_kaalia ALL=(root) NOPASSWD: /usr/sbin/iptables-save *
```

## VM/Virtualization Management

```sudoers
vastai_kaalia ALL=(root) NOPASSWD: /var/lib/vastai_kaalia/enable_vms.py *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/virsh *
```

## Process Management

```sudoers
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/kill *
```

## Disk I/O Benchmarking

```sudoers
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/dd if=/dev/zero of=/var/lib/docker/* *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/dd if=/var/lib/docker/* of=/var/lib/docker/* *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/rm /var/lib/docker/tmpfile*
vastai_kaalia ALL=(root) NOPASSWD: /usr/sbin/hdparm -t *
```

## Script Updates

```sudoers
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemd-run --scope --unit=vastai_script_updater sh -c *
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemd-run --scope --unit=vastai_script_updater *
```

## Hardware Information

```sudoers
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/lshw *
```

## Systemctl Service Management

```sudoers
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemctl stop vastai
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemctl start vastai
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemctl restart vastai
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemctl status vastai
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemctl enable vastai
vastai_kaalia ALL=(root) NOPASSWD: /usr/bin/systemctl daemon-reload
```
