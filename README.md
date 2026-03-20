# SYN Flood Detection Engine

A real-time SYN flood detection tool built in Python that reads live kernel telemetry from the Linux `/proc` filesystem to detect TCP-based DoS attacks without any external dependencies.

## Lab Environment

| Component | Details |
|-----------|---------|
| Victim/Defender | Ubuntu VM — 192.168.56.104 |
| Attacker | Kali Linux VM — 192.168.56.103 |
| Network | VirtualBox Host-Only Network |
| Attack Tool | hping3 |

## How It Works

The detector reads two kernel files every second:
- `/proc/net/snmp` — TCP metrics (PassiveOpens, AttemptFails, CurrEstab)
- `/proc/net/netstat` — Extended TCP metrics (SyncookiesSent, ListenOverflows)

### Detection Pipeline
Start → Baseline Learning (30s) → Monitoring Mode → Anomaly Detection → Alert
### Metrics Tracked
| Metric | Source | Purpose |
|--------|--------|---------|
| PassiveOpens | /proc/net/snmp | Incoming connection attempts |
| AttemptFails | /proc/net/snmp | Failed handshakes |
| CurrEstab | /proc/net/snmp | Active connections |
| SyncookiesSent | /proc/net/netstat | Kernel SYN cookie activations |
| ListenOverflows | /proc/net/netstat | Backlog queue overflows |

## Detection Logic

### Severity Levels
| Level | Condition |
|-------|-----------|
| WARNING | SYN rate > 2x baseline |
| ALERT | SYN rate > 3x baseline OR cookies rising OR high fails |
| CRITICAL | SYN rate > 5x baseline OR listen overflow detected |

### Completion Ratio
If `SYN rate > 0` and `ESTAB/SYN < 0.3` → SYN flood suspected
(Low completion ratio = connections attempted but never completed)

## Attack Experiments

### Results Before Hardening

| Attack Type | Command | Fail/sec | Cookie/sec | Detected |
|-------------|---------|----------|------------|---------|
| Slow SYN | `--interval u500000` | ~2 | 0 | No |
| Burst | `--faster` | ~12,000 | 0 | Yes |
| Full Flood | `--flood` | ~27,700 | ~25,217 | Yes |

### Results After Hardening

| Metric | Before | After | Reduction |
|--------|--------|-------|-----------|
| Fail/sec | 27,700 | ~15 | 99.9% |
| Cookie/sec | 25,217 | 0 | 100% |

## System Hardening

```bash
# Increase SYN backlog queue
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=2048

# Reduce SYN-ACK retries
sudo sysctl -w net.ipv4.tcp_synack_retries=2

# Reduce SYN retries
sudo sysctl -w net.ipv4.tcp_syn_retries=3

# iptables rate limiting — allow 10 SYN/sec, drop the rest
sudo iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
sudo iptables -A INPUT -p tcp --syn -j DROP
```

## Known Limitations

- **Slow SYN attacks evade detection** — low rate stays below threshold. Mitigation: time-window analysis
- **Zero baseline in isolated lab** — no background traffic in controlled environment. Real deployment would learn from live traffic
- **Hardcoded poll interval** — currently 1 second. Sub-second attacks may be partially missed

## Usage

```bash
python3 telemetry_reader.py
```

Requires root or sudo for full /proc access on some systems.

## Requirements

- Python 3.x
- Linux system (reads from /proc filesystem)
- No external dependencies