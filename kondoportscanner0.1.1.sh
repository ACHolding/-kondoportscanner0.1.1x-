#!/usr/bin/env bash
# kondoportscanner0.1.1x — TCP connect port scanner (bash /dev/tcp)
# Use only on hosts you own or are explicitly authorized to test.
# Compatible with bash 3.2+ (macOS default).
#
# Re-exec under bash when launched as `sh script.sh` (macOS /bin/sh is not bash).
if [ -z "${BASH_VERSION:-}" ]; then
  if command -v bash >/dev/null 2>&1; then
    exec bash "$0" "$@"
  fi
  printf 'kondoportscanner0.1.1x: requires bash\n' >&2
  exit 1
fi

set -euo pipefail

TOOL_NAME="kondoportscanner0.1.1x"
TOOL_VERSION="0.1.1x"

DEFAULT_TIMEOUT=1
DEFAULT_CONCURRENCY=50
COMMON_PORTS="21 22 23 25 53 80 110 111 135 139 143 443 445 993 995 1723 3306 3389 5432 5900 8080 8443"

usage() {
  cat <<EOF
${TOOL_NAME} v${TOOL_VERSION}
TCP connect port scanner using bash /dev/tcp.

Usage:
  $(basename "$0") -H <host> [options]

Options:
  -H, --host <host>         Target hostname or IP (required)
  -p, --ports <spec>        Ports: 80 | 22,80,443 | 1-1024 | mix (default: common)
  -t, --timeout <sec>       Connect timeout in seconds (default: ${DEFAULT_TIMEOUT})
  -c, --concurrency <n>     Parallel probes (default: ${DEFAULT_CONCURRENCY})
  -o, --open-only           Print only open ports
  -q, --quiet               Suppress banner / progress
  -h, --help                Show this help

Examples:
  $(basename "$0") -H 127.0.0.1
  $(basename "$0") -H example.com -p 22,80,443
  $(basename "$0") -H 192.168.1.1 -p 1-1024 -t 2 -c 100

Only scan systems you are authorized to test.
EOF
}

die() {
  printf '%s: %s\n' "$TOOL_NAME" "$*" >&2
  exit 1
}

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

# Expand "22,80,443,8000-8010" into a sorted unique list of ports (stdout).
parse_ports() {
  local spec="$1"
  local part lo hi p
  local -a out
  out=()

  # bash 3.2-safe CSV split
  local IFS=','
  set -- $spec
  for part in "$@"; do
    part="$(printf '%s' "$part" | tr -d '[:space:]')"
    [ -n "$part" ] || continue

    case "$part" in
      *-*)
        lo="${part%-*}"
        hi="${part#*-}"
        is_int "$lo" && is_int "$hi" || die "invalid port range: $part"
        [ "$lo" -ge 1 ] && [ "$hi" -le 65535 ] && [ "$lo" -le "$hi" ] \
          || die "invalid port range: $part"
        p="$lo"
        while [ "$p" -le "$hi" ]; do
          out[${#out[@]}]="$p"
          p=$((p + 1))
        done
        ;;
      *)
        is_int "$part" || die "invalid port: $part"
        [ "$part" -ge 1 ] && [ "$part" -le 65535 ] || die "invalid port: $part"
        out[${#out[@]}]="$part"
        ;;
    esac
  done

  [ "${#out[@]}" -gt 0 ] || die "no ports to scan"
  printf '%s\n' "${out[@]}" | sort -n | uniq
}

# Pure-bash connect with timeout (no GNU coreutils required).
probe_port() {
  local host="$1"
  local port="$2"
  local timeout_sec="$3"
  local result_file="$4"
  local connect_pid killer_pid status

  (
    exec 3<>"/dev/tcp/${host}/${port}"
  ) >/dev/null 2>&1 &
  connect_pid=$!

  (
    sleep "$timeout_sec"
    kill "$connect_pid" 2>/dev/null || true
  ) &
  killer_pid=$!

  set +e
  wait "$connect_pid" 2>/dev/null
  status=$?
  set -e
  kill "$killer_pid" 2>/dev/null || true
  wait "$killer_pid" 2>/dev/null || true

  if [ "$status" -eq 0 ]; then
    printf 'open\n' >"$result_file"
  else
    printf 'closed\n' >"$result_file"
  fi
}

running_jobs() {
  jobs -pr 2>/dev/null | wc -l | tr -d ' '
}

wait_slot() {
  local max="$1"
  while [ "$(running_jobs)" -ge "$max" ]; do
    sleep 0.05
  done
}

main() {
  local host=""
  local port_spec=""
  local timeout_sec="$DEFAULT_TIMEOUT"
  local concurrency="$DEFAULT_CONCURRENCY"
  local open_only=0
  local quiet=0

  while [ "$#" -gt 0 ]; do
    case "$1" in
      -H|--host)
        [ "$#" -ge 2 ] || die "missing value for $1"
        host="$2"
        shift 2
        ;;
      -p|--ports)
        [ "$#" -ge 2 ] || die "missing value for $1"
        port_spec="$2"
        shift 2
        ;;
      -t|--timeout)
        [ "$#" -ge 2 ] || die "missing value for $1"
        timeout_sec="$2"
        shift 2
        ;;
      -c|--concurrency)
        [ "$#" -ge 2 ] || die "missing value for $1"
        concurrency="$2"
        shift 2
        ;;
      -o|--open-only)
        open_only=1
        shift
        ;;
      -q|--quiet)
        quiet=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown option: $1 (try --help)"
        ;;
    esac
  done

  [ -n "$host" ] || die "host required (-H). Try --help."
  [[ "$timeout_sec" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "invalid timeout: $timeout_sec"
  is_int "$concurrency" && [ "$concurrency" -ge 1 ] || die "invalid concurrency: $concurrency"
  [ -n "${BASH_VERSION:-}" ] || die "must be run with bash"

  local -a ports
  ports=()
  if [ -z "$port_spec" ]; then
    # shellcheck disable=SC2086
    set -- $COMMON_PORTS
    ports=("$@")
  else
    # Avoid process substitution so older parsers / wrappers stay happier;
    # bash is still required for /dev/tcp.
    local portlist_file
    portlist_file="$(mktemp "${TMPDIR:-/tmp}/${TOOL_NAME}.ports.XXXXXX")"
    parse_ports "$port_spec" >"$portlist_file"
    while IFS= read -r p; do
      [ -n "$p" ] || continue
      ports[${#ports[@]}]="$p"
    done <"$portlist_file"
    rm -f "$portlist_file"
  fi

  local tmpdir
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/${TOOL_NAME}.XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmpdir'" EXIT

  if [ "$quiet" -eq 0 ]; then
    printf '%s v%s\n' "$TOOL_NAME" "$TOOL_VERSION"
    printf 'Target: %s | Ports: %d | Timeout: %ss | Concurrency: %d\n' \
      "$host" "${#ports[@]}" "$timeout_sec" "$concurrency"
    printf 'Scanning...\n'
  fi

  local port result_file
  local open_count=0
  local start_ts end_ts elapsed
  start_ts="$(date +%s)"

  for port in "${ports[@]}"; do
    wait_slot "$concurrency"
    result_file="${tmpdir}/${port}"
    probe_port "$host" "$port" "$timeout_sec" "$result_file" &
  done
  wait

  end_ts="$(date +%s)"
  elapsed=$((end_ts - start_ts))

  local state
  for port in "${ports[@]}"; do
    result_file="${tmpdir}/${port}"
    if [ -f "$result_file" ]; then
      state="$(cat "$result_file")"
    else
      state="closed"
    fi

    if [ "$state" = "open" ]; then
      open_count=$((open_count + 1))
      printf '%-6s open\n' "$port"
    elif [ "$open_only" -eq 0 ] && [ "$quiet" -eq 0 ]; then
      printf '%-6s closed\n' "$port"
    fi
  done

  if [ "$quiet" -eq 0 ]; then
    printf 'Done: %d open / %d scanned in %ds\n' "$open_count" "${#ports[@]}" "$elapsed"
  fi

  if [ "$open_count" -gt 0 ]; then
    return 0
  fi
  return 1
}

main "$@"
