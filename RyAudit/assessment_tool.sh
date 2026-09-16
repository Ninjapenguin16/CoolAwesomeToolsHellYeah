#!/usr/bin/env bash

set -u   # catch unset variables. We avoid 'set -e' so one failed check
         # does not stop the whole assessment.

TOOL_NAME="RyAudit"

zenity --info --width=360 --title="$TOOL_NAME" \
       --text="$TOOL_NAME has started." \
       2>/dev/null || echo "[$TOOL_NAME] started"

# Cache the sudo password once so later checks run smoothly.
sudo -v

WORKDIR="$HOME/${TOOL_NAME}_reports"
mkdir -p "$WORKDIR"
REPORT="$WORKDIR/report_$(date +%F_%H%M%S).txt"
touch "$REPORT"

log()     { echo "$*" | tee -a "$REPORT"; }
section() { log ""; log "===== $* ====="; }

log "$TOOL_NAME security report"
log "Generated : $(date)"
log "Host      : $(hostname)"
log "Run by    : $(whoami)"

section "System administration"
log "Operating system : $(uname -srm)"
log "Uptime           : $(uptime -p)"
log "Disk usage on / :"
df -h / | tee -a "$REPORT"
log "Accounts with root privileges (UID 0):"
awk -F: '$3==0 {print " " $1}' /etc/passwd | tee -a "$REPORT"
log "Members of the sudo group:"
getent group sudo | cut -d: -f4 | tr ',' '\n' | sed 's/^/ /' | tee -a "$REPORT"
UPGRADES=$(apt list --upgradable 2>/dev/null | tail -n +2 | wc -l)
log "Packages that can be upgraded: $UPGRADES"

section "Process control"
log "Total running processes: $(ps -e --no-headers | wc -l)"
log "Top 5 processes by CPU:"
ps -eo pid,comm,%cpu --sort=-%cpu | head -n 6 | tee -a "$REPORT"
log "Top 5 processes by memory:"
ps -eo pid,comm,%mem --sort=-%mem | head -n 6 | tee -a "$REPORT"
log "Network services that are listening:"
ss -tuln | tee -a "$REPORT"
log "Starting a temporary background watcher..."
sleep 120 &
WATCHER_PID=$!
log " watcher started as PID $WATCHER_PID"
kill "$WATCHER_PID" 2>/dev/null && log " watcher (PID $WATCHER_PID) stopped"

section "File and permission audit"
WORLD_WRITABLE=$(find /home -xdev -type f -perm -0002 2>/dev/null | wc -l)
log "World writable files under /home: $WORLD_WRITABLE"
find /home -xdev -type f -perm -0002 2>/dev/null | sed 's/^/ /' | tee -a "$REPORT"
log "SUID programs under /usr/bin and /usr/sbin:"
find /usr/bin /usr/sbin -xdev -type f -perm -4000 2>/dev/null | sed 's/^/ /' | tee
-a "$REPORT"
log "Permissions on sensitive files:"
ls -l /etc/passwd /etc/shadow | tee -a "$REPORT"

section "Hardening actions"
if command -v ufw >/dev/null; then
    sudo ufw --force enable         >/dev/null
    sudo ufw default deny incoming  >/dev/null
    sudo ufw default allow outgoing >/dev/null
    FW_ENABLED=1
    log "Firewall (ufw) enabled with default deny incoming."
    sudo ufw status verbose | tee -a "$REPORT"
else
    FW_ENABLED=0
    log "ufw is not installed. Install: sudo apt install ufw"
fi

FAILED=$(sudo grep "Failed password" /var/log/auth.log 2>/dev/null | wc -l)
log "Failed SSH login attempts on record: $FAILED"

EMPTY=$(sudo awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | wc -l)
log "Accounts with an EMPTY password: $EMPTY (should be 0)"

section "Security score"
SCORE=100
[ "$UPGRADES"       -gt 0  ] && SCORE=$((SCORE - 10))
[ "$WORLD_WRITABLE" -gt 0  ] && SCORE=$((SCORE - 15))
[ "$FAILED"         -gt 20 ] && SCORE=$((SCORE - 10))
[ "$EMPTY"          -gt 0  ] && SCORE=$((SCORE - 30))
[ "$FW_ENABLED"     -eq 0  ] && SCORE=$((SCORE - 20))
[ "$SCORE" -lt 0 ] && SCORE=0

if   [ "$SCORE" -ge 90 ]; then RATING="STRONG"
elif [ "$SCORE" -ge 70 ]; then RATING="MODERATE"
else                           RATING="NEEDS WORK"
fi
log "Security score: $SCORE / 100 ($RATING)"

section "Finishing up"
chmod 600 "$REPORT"
log "Report locked to owner only (chmod 600)."
log "Report saved to: $REPORT"

zenity --info --width=420 --title="$TOOL_NAME" \
       --text="$TOOL_NAME has completed."$'\n'"Security score: $SCORE / 100

($RATING)" \
       2>/dev/null || echo "[$TOOL_NAME] completed. Score: $SCORE/100"

# --- Section 11: GitHub (do this in the terminal, not in the script) ---------
#   git init
#   git add .
#   git commit -m "Version 1.0 of my Linux Security Assessment Tool"
#   git branch -M main
#   git remote add origin <your repo URL>
#   git push -u origin main
