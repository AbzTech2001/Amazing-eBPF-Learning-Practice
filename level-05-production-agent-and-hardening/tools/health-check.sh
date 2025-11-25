#!/bin/bash
# Health check for production eBPF agent

set -e

# Configuration
AGENT_NAME=${AGENT_NAME:-"ebpf-agent"}
AGENT_PORT=${AGENT_PORT:-8080}
METRICS_PORT=${METRICS_PORT:-9090}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    local status=$1
    local message=$2

    case $status in
        ok)
            echo -e "${GREEN}✓${NC} $message"
            return 0
            ;;
        warn)
            echo -e "${YELLOW}⚠${NC} $message"
            return 1
            ;;
        fail)
            echo -e "${RED}✗${NC} $message"
            return 1
            ;;
    esac
}

echo "========================================="
echo "eBPF Agent Health Check"
echo "========================================="
echo ""

HEALTH_SCORE=0
MAX_SCORE=0

echo "=== Process Status ==="
MAX_SCORE=$((MAX_SCORE + 1))

# Check if agent is running
if pgrep -x "$AGENT_NAME" > /dev/null; then
    PID=$(pgrep -x "$AGENT_NAME")
    UPTIME=$(ps -p $PID -o etime= | tr -d ' ')
    print_status "ok" "Agent is running (PID: $PID, Uptime: $UPTIME)"
    HEALTH_SCORE=$((HEALTH_SCORE + 1))
else
    print_status "fail" "Agent is not running"
fi

echo ""
echo "=== Resource Usage ==="
MAX_SCORE=$((MAX_SCORE + 2))

if pgrep -x "$AGENT_NAME" > /dev/null; then
    PID=$(pgrep -x "$AGENT_NAME")

    # Check CPU usage
    CPU=$(ps -p $PID -o %cpu= | tr -d ' ')
    CPU_INT=${CPU%.*}
    if [ "$CPU_INT" -lt 20 ]; then
        print_status "ok" "CPU usage: ${CPU}%"
        HEALTH_SCORE=$((HEALTH_SCORE + 1))
    elif [ "$CPU_INT" -lt 50 ]; then
        print_status "warn" "CPU usage: ${CPU}% (consider optimization)"
    else
        print_status "fail" "CPU usage: ${CPU}% (too high!)"
    fi

    # Check memory usage
    MEM=$(ps -p $PID -o %mem= | tr -d ' ')
    RSS=$(ps -p $PID -o rss= | tr -d ' ')
    RSS_MB=$((RSS / 1024))
    MEM_INT=${MEM%.*}

    if [ "$MEM_INT" -lt 5 ]; then
        print_status "ok" "Memory usage: ${MEM}% (${RSS_MB} MB)"
        HEALTH_SCORE=$((HEALTH_SCORE + 1))
    elif [ "$MEM_INT" -lt 10 ]; then
        print_status "warn" "Memory usage: ${MEM}% (${RSS_MB} MB)"
    else
        print_status "fail" "Memory usage: ${MEM}% (${RSS_MB} MB - possible leak)"
    fi
fi

echo ""
echo "=== BPF Programs ==="
MAX_SCORE=$((MAX_SCORE + 1))

# Check if BPF programs are loaded
PROG_COUNT=$(sudo bpftool prog list 2>/dev/null | grep -c "name" || echo 0)
if [ "$PROG_COUNT" -gt 0 ]; then
    print_status "ok" "$PROG_COUNT BPF programs loaded"
    HEALTH_SCORE=$((HEALTH_SCORE + 1))

    echo ""
    echo "Loaded programs:"
    sudo bpftool prog list 2>/dev/null | grep "name" | head -10
else
    print_status "warn" "No BPF programs loaded"
fi

echo ""
echo "=== BPF Maps ==="
MAX_SCORE=$((MAX_SCORE + 1))

# Check if BPF maps exist
MAP_COUNT=$(sudo bpftool map list 2>/dev/null | grep -c "id" || echo 0)
if [ "$MAP_COUNT" -gt 0 ]; then
    print_status "ok" "$MAP_COUNT BPF maps loaded"
    HEALTH_SCORE=$((HEALTH_SCORE + 1))
else
    print_status "warn" "No BPF maps loaded"
fi

echo ""
echo "=== Network Connectivity ==="
MAX_SCORE=$((MAX_SCORE + 1))

# Check health endpoint if agent has one
if [ -n "$AGENT_PORT" ]; then
    if curl -sf http://localhost:$AGENT_PORT/health > /dev/null 2>&1; then
        print_status "ok" "Health endpoint responding on :$AGENT_PORT"
        HEALTH_SCORE=$((HEALTH_SCORE + 1))
    else
        print_status "warn" "Health endpoint not responding on :$AGENT_PORT"
    fi
fi

# Check metrics endpoint
MAX_SCORE=$((MAX_SCORE + 1))
if [ -n "$METRICS_PORT" ]; then
    if curl -sf http://localhost:$METRICS_PORT/metrics > /dev/null 2>&1; then
        print_status "ok" "Metrics endpoint responding on :$METRICS_PORT"
        HEALTH_SCORE=$((HEALTH_SCORE + 1))

        # Sample some metrics
        echo ""
        echo "Sample metrics:"
        curl -s http://localhost:$METRICS_PORT/metrics 2>/dev/null | grep -E "^[^#]" | head -5
    else
        print_status "warn" "Metrics endpoint not responding on :$METRICS_PORT"
    fi
fi

echo ""
echo "=== Error Check ==="
MAX_SCORE=$((MAX_SCORE + 1))

# Check kernel logs for BPF errors
RECENT_ERRORS=$(sudo dmesg -T | grep -i "bpf" | grep -i "error\|failed\|denied" | tail -5)
if [ -z "$RECENT_ERRORS" ]; then
    print_status "ok" "No recent BPF errors in kernel log"
    HEALTH_SCORE=$((HEALTH_SCORE + 1))
else
    print_status "warn" "Found BPF errors in kernel log:"
    echo "$RECENT_ERRORS"
fi

echo ""
echo "========================================="
PERCENTAGE=$((HEALTH_SCORE * 100 / MAX_SCORE))
echo "Health Score: $HEALTH_SCORE / $MAX_SCORE ($PERCENTAGE%)"
echo "========================================="
echo ""

if [ "$PERCENTAGE" -ge 80 ]; then
    echo -e "${GREEN}✓ Agent is healthy${NC}"
    exit 0
elif [ "$PERCENTAGE" -ge 50 ]; then
    echo -e "${YELLOW}⚠ Agent has warnings${NC}"
    exit 1
else
    echo -e "${RED}✗ Agent is unhealthy${NC}"
    exit 2
fi
