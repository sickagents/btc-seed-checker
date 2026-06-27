#!/usr/bin/env python3
"""
Bitcoin Seed Phrase Balance Checker V.2 — High Performance Edition
Optimized for multi-core servers (100+ vCPU).
Concurrent API calls, multi-worker architecture, headless CLI.
"""

import os
import sys
import json
import time
import hashlib
import hmac
import struct
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from collections import deque

# ── Config ────────────────────────────────────────────────────────────────────

MNEMONIC_BITS = 128          # 12 words (use 256 for 24 words)
DERIVE_START = 0
DERIVE_END = 20
WORKER_THREADS = 80          # Mnemonic generators
API_CONCURRENCY = 50         # Concurrent API calls per mnemonic batch
API_DELAY = 0.15             # Delay between API calls per thread (rate limit)
API_TIMEOUT = 8              # Seconds per API request
MAX_RETRIES = 2              # Retries per failed API call
SAVE_FILE = "sukses.txt"
STATS_INTERVAL = 5           # Print stats every N seconds

# ── BIP39 ─────────────────────────────────────────────────────────────────────

WORDLIST = None

def load_wordlist():
    global WORDLIST
    try:
        from mnemonic import Mnemonic
        WORDLIST = Mnemonic("english").wordlist
    except ImportError:
        url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
        resp = requests.get(url, timeout=10)
        WORDLIST = resp.text.strip().split("\n")

def generate_entropy(bits=128):
    return os.urandom(bits // 8)

def entropy_to_mnemonic(entropy):
    entropy_bits = len(entropy) * 8
    checksum_bits = entropy_bits // 32
    hash_bytes = hashlib.sha256(entropy).digest()
    hash_bits = bin(int.from_bytes(hash_bytes, 'big'))[2:].zfill(256)
    entropy_bits_str = bin(int.from_bytes(entropy, 'big'))[2:].zfill(entropy_bits)
    all_bits = entropy_bits_str + hash_bits[:checksum_bits]
    words = []
    for i in range(0, len(all_bits), 11):
        idx = int(all_bits[i:i+11], 2)
        words.append(WORDLIST[idx])
    return " ".join(words)

def mnemonic_to_seed(mnemonic, passphrase=""):
    return hashlib.pbkdf2_hmac(
        "sha512", mnemonic.encode("utf-8"),
        ("mnemonic" + passphrase).encode("utf-8"),
        2048, dklen=64
    )

# ── HD Key Derivation (BIP32) ────────────────────────────────────────────────

def hmac_sha512(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()

def ser32(i):
    return struct.pack(">I", i)

def parse256(b):
    return int.from_bytes(b, 'big')

ECDSA_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_pubkey_cache = {}

def secp256k1_public_key(private_key_bytes, compressed=True):
    key_hex = private_key_bytes.hex()
    if key_hex in _pubkey_cache:
        return _pubkey_cache[key_hex]
    
    import ecdsa
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    if compressed:
        x = vk.to_string()[:32]
        y = vk.to_string()[32:]
        prefix = b'\x02' if y[-1] % 2 == 0 else b'\x03'
        result = prefix + x
    else:
        result = b'\x04' + vk.to_string()
    
    _pubkey_cache[key_hex] = result
    return result

def master_key_from_seed(seed):
    I = hmac_sha512(b"Bitcoin seed", seed)
    return I[:32], I[32:]

def ckd_priv(parent_key, parent_chain, index):
    if index >= 0x80000000:
        data = b'\x00' + parent_key + ser32(index)
    else:
        parent_pub = secp256k1_public_key(parent_key)
        data = parent_pub + ser32(index)
    I = hmac_sha512(parent_chain, data)
    IL, IR = I[:32], I[32:]
    child_key = (parse256(IL) + parse256(parent_key)) % ECDSA_ORDER
    child_key_bytes = child_key.to_bytes(32, 'big')
    if not (0 < parse256(IL) < ECDSA_ORDER) or not (0 < child_key < ECDSA_ORDER):
        return None, None
    return child_key_bytes, IR

def derive_path(seed, path):
    key, chain = master_key_from_seed(seed)
    for index in path:
        if key is None:
            return None, None
        key, chain = ckd_priv(key, chain, index)
    return key, chain

# ── Address Generation ───────────────────────────────────────────────────────

def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(data):
    n = int.from_bytes(data, 'big')
    result = ''
    while n > 0:
        n, r = divmod(n, 58)
        result = B58[r] + result
    for byte in data:
        if byte == 0:
            result = '1' + result
        else:
            break
    return result

def base58check_encode(version, payload):
    data = bytes([version]) + payload
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    return base58_encode(data + checksum)

def bech32_encode(hrp, witver, witprog):
    CS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    def polymod(values):
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ v
            for i in range(5):
                chk ^= GEN[i] if ((b >> i) & 1) else 0
        return chk
    def hrp_expand(h):
        return [ord(x) >> 5 for x in h] + [0] + [ord(x) & 31 for x in h]
    data = [witver]
    acc, bits = 0, 0
    for b in witprog:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits > 0:
        data.append((acc << (5 - bits)) & 31)
    pv = polymod(hrp_expand(hrp) + data + [0]*6) ^ 1
    data += [(pv >> 5*(5-i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CS[d] for d in data)

def pubkey_to_p2pkh(pubkey):
    return base58check_encode(0x00, hash160(pubkey))

def pubkey_to_p2sh_p2wpkh(pubkey):
    witness = hash160(pubkey)
    return base58check_encode(0x05, hash160(b'\x00\x14' + witness))

def pubkey_to_p2wpkh(pubkey):
    return bech32_encode("bc", 0, hash160(pubkey))

# ── Balance Checking ─────────────────────────────────────────────────────────

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})

# API endpoints with rate limit awareness
API_ENDPOINTS = [
    {"name": "blockstream", "url": "https://blockstream.info/api/address/{addr}"},
    {"name": "mempool",     "url": "https://mempool.space/api/address/{addr}"},
]

def check_balance_single(address, timeout=API_TIMEOUT, retries=MAX_RETRIES):
    """Check balance for a single address. Returns (balance_btc, api_name) or (None, error)."""
    for api in API_ENDPOINTS:
        for attempt in range(retries + 1):
            try:
                url = api["url"].format(addr=address)
                resp = session.get(url, timeout=timeout)
                if resp.status_code == 200:
                    d = resp.json()
                    funded = d.get("chain_stats", {}).get("funded_txo_sum", 0)
                    spent = d.get("chain_stats", {}).get("spent_txo_sum", 0)
                    balance = (funded - spent) / 1e8
                    return balance, api["name"]
                elif resp.status_code == 429:
                    time.sleep(2 * (attempt + 1))
                    continue
                else:
                    break
            except requests.exceptions.Timeout:
                time.sleep(0.5)
                continue
            except Exception:
                break
    return None, "failed"

def check_balances_batch(addresses, concurrency=API_CONCURRENCY):
    """Check multiple addresses concurrently. Returns list of (address, balance, api)."""
    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {}
        for addr in addresses:
            f = pool.submit(check_balance_single, addr)
            futures[f] = addr
            time.sleep(API_DELAY)  # Stagger requests
        
        for future in as_completed(futures):
            addr = futures[future]
            try:
                balance, api_info = future.result()
                results.append((addr, balance, api_info))
            except Exception as e:
                results.append((addr, None, str(e)))
    return results

# ── Global Stats ─────────────────────────────────────────────────────────────

class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.mnemonics_processed = 0
        self.addresses_checked = 0
        self.api_calls = 0
        self.api_errors = 0
        self.found = 0
        self.start_time = time.time()
        self.recent_times = deque(maxlen=100)
    
    def record_mnemonic(self, n_addresses, elapsed):
        with self.lock:
            self.mnemonics_processed += 1
            self.addresses_checked += n_addresses
            self.api_calls += n_addresses
            self.recent_times.append(elapsed)
    
    def record_api_error(self):
        with self.lock:
            self.api_errors += 1
    
    def record_found(self):
        with self.lock:
            self.found += 1
    
    def get_stats(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            mnemonics_per_sec = self.mnemonics_processed / elapsed if elapsed > 0 else 0
            api_per_sec = self.api_calls / elapsed if elapsed > 0 else 0
            avg_time = sum(self.recent_times) / len(self.recent_times) if self.recent_times else 0
            return {
                "elapsed": elapsed,
                "mnemonics": self.mnemonics_processed,
                "addresses": self.addresses_checked,
                "api_calls": self.api_calls,
                "api_errors": self.api_errors,
                "found": self.found,
                "mnemonics_per_sec": mnemonics_per_sec,
                "mnemonics_per_hour": mnemonics_per_sec * 3600,
                "api_per_sec": api_per_sec,
                "avg_time_per_mnemonic": avg_time,
            }

stats = Stats()

# ── Save Lock ────────────────────────────────────────────────────────────────

save_lock = threading.Lock()

def save_success(mnemonic, bip_name, index, address, balance):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = (
        f"{'=' * 60}\n"
        f"FOUND: {timestamp}\n"
        f"Mnemonic: {mnemonic}\n"
        f"Type: {bip_name} (index {index})\n"
        f"Address: {address}\n"
        f"Balance: {balance:.8f} BTC\n"
        f"{'=' * 60}\n\n"
    )
    with save_lock:
        with open(SAVE_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
    print(f"\n{'!'*60}")
    print(f"  *** FOUND WALLET WITH BALANCE! ***")
    print(f"  Mnemonic: {mnemonic}")
    print(f"  {bip_name}[{index}]: {address} = {balance:.8f} BTC")
    print(f"  Saved to {SAVE_FILE}")
    print(f"{'!'*60}\n")

# ── Worker ───────────────────────────────────────────────────────────────────

def process_mnemonic(mnemonic):
    """Generate all addresses for a mnemonic and check balances."""
    t0 = time.time()
    
    seed = mnemonic_to_seed(mnemonic)
    
    # Derivation paths
    paths = {
        "BIP44":  [0x8000002C, 0x80000000, 0x80000000, 0],
        "BIP49":  [0x80000031, 0x80000000, 0x80000000, 0],
        "BIP84":  [0x80000054, 0x80000000, 0x80000000, 0],
    }
    
    address_map = {}  # address -> (bip_name, index)
    all_addresses = []
    
    # Generate all addresses
    for bip_name, base_path in paths.items():
        for i in range(DERIVE_START, DERIVE_END + 1):
            full_path = base_path + [i]
            key, chain = derive_path(seed, full_path)
            if key is None:
                continue
            pubkey = secp256k1_public_key(key)
            
            if bip_name == "BIP44":
                addr = pubkey_to_p2pkh(pubkey)
            elif bip_name == "BIP49":
                addr = pubkey_to_p2sh_p2wpkh(pubkey)
            else:
                addr = pubkey_to_p2wpkh(pubkey)
            
            address_map[addr] = (bip_name, i)
            all_addresses.append(addr)
    
    # Check balances in parallel
    results = check_balances_batch(all_addresses)
    
    found_any = False
    for addr, balance, api_info in results:
        if balance is not None and balance > 0:
            bip_name, idx = address_map[addr]
            save_success(mnemonic, bip_name, idx, addr, balance)
            found_any = True
        elif balance is None:
            stats.record_api_error()
    
    elapsed = time.time() - t0
    stats.record_mnemonic(len(all_addresses), elapsed)
    
    return found_any

def worker(worker_id, stop_event):
    """Worker thread that continuously generates and checks mnemonics."""
    bits = MNEMONIC_BITS
    while not stop_event.is_set():
        try:
            entropy = generate_entropy(bits)
            mnemonic = entropy_to_mnemonic(entropy)
            process_mnemonic(mnemonic)
        except Exception as e:
            time.sleep(0.5)

# ── Stats Printer ────────────────────────────────────────────────────────────

def stats_printer(stop_event):
    """Print live stats periodically."""
    while not stop_event.is_set():
        stop_event.wait(STATS_INTERVAL)
        if stop_event.is_set():
            break
        s = stats.get_stats()
        elapsed = str(timedelta(seconds=int(s["elapsed"])))
        print(
            f"[{elapsed}] "
            f"Mnemonics: {s['mnemonics']:,} | "
            f"Addresses: {s['addresses']:,} | "
            f"API: {s['api_calls']:,} ({s['api_per_sec']:.0f}/s) | "
            f"Errors: {s['api_errors']:,} | "
            f"Found: {s['found']} | "
            f"Rate: {s['mnemonics_per_hour']:,.0f}/hr "
            f"({s['avg_time_per_mnemonic']:.1f}s/mnemonic)"
        )

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    global WORKER_THREADS, API_CONCURRENCY, MNEMONIC_BITS, DERIVE_START, DERIVE_END, API_DELAY
    
    # Parse CLI args
    import argparse
    parser = argparse.ArgumentParser(description="Bitcoin Seed Phrase Balance Checker V.2 — High Performance")
    parser.add_argument("-w", "--workers", type=int, default=WORKER_THREADS, help=f"Mnemonic worker threads (default: {WORKER_THREADS})")
    parser.add_argument("-c", "--concurrency", type=int, default=API_CONCURRENCY, help=f"API concurrency per batch (default: {API_CONCURRENCY})")
    parser.add_argument("-b", "--bits", type=int, choices=[128, 256], default=MNEMONIC_BITS, help="Entropy bits: 128=12 words, 256=24 words (default: 128)")
    parser.add_argument("-s", "--start", type=int, default=DERIVE_START, help=f"Derivation start index (default: {DERIVE_START})")
    parser.add_argument("-e", "--end", type=int, default=DERIVE_END, help=f"Derivation end index (default: {DERIVE_END})")
    parser.add_argument("--delay", type=float, default=API_DELAY, help=f"API request delay in seconds (default: {API_DELAY})")
    args = parser.parse_args()
    
    WORKER_THREADS = args.workers
    API_CONCURRENCY = args.concurrency
    MNEMONIC_BITS = args.bits
    DERIVE_START = args.start
    DERIVE_END = args.end
    API_DELAY = args.delay
    
    word_count = 12 if MNEMONIC_BITS == 128 else 24
    addrs_per_mnemonic = 3 * (DERIVE_END - DERIVE_START + 1)
    
    print("=" * 70)
    print("  Bitcoin Seed Phrase Balance Checker V.2 — High Performance")
    print("=" * 70)
    print(f"  Mnemonic:          {word_count} words ({MNEMONIC_BITS}-bit)")
    print(f"  Derivation range:  {DERIVE_START} - {DERIVE_END}")
    print(f"  Addresses/mnemonic:{addrs_per_mnemonic} (BIP44 + BIP49 + BIP84)")
    print(f"  Worker threads:    {WORKER_THREADS}")
    print(f"  API concurrency:   {API_CONCURRENCY}")
    print(f"  API delay:         {API_DELAY}s")
    print(f"  Output file:       {SAVE_FILE}")
    print("=" * 70)
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Press Ctrl+C to stop")
    print("=" * 70)
    print()
    
    # Load dependencies
    print("Loading dependencies...")
    try:
        import ecdsa
    except ImportError:
        print("Installing ecdsa...")
        os.system(f"{sys.executable} -m pip install ecdsa -q")
    
    load_wordlist()
    print(f"BIP39 wordlist: {len(WORDLIST)} words")
    print(f"Starting {WORKER_THREADS} workers...")
    print()
    
    stop_event = threading.Event()
    
    # Start stats printer
    stats_thread = threading.Thread(target=stats_printer, args=(stop_event,), daemon=True)
    stats_thread.start()
    
    # Start workers
    workers = []
    for i in range(WORKER_THREADS):
        t = threading.Thread(target=worker, args=(i, stop_event), daemon=True)
        t.start()
        workers.append(t)
    
    # Wait for Ctrl+C
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nStopping...")
        stop_event.set()
    
    # Wait for workers to finish
    for t in workers:
        t.join(timeout=5)
    
    # Final stats
    s = stats.get_stats()
    elapsed = str(timedelta(seconds=int(s["elapsed"])))
    print(f"\n{'=' * 70}")
    print(f"  FINAL STATISTICS")
    print(f"{'=' * 70}")
    print(f"  Runtime:           {elapsed}")
    print(f"  Mnemonics checked: {s['mnemonics']:,}")
    print(f"  Addresses checked: {s['addresses']:,}")
    print(f"  API calls:         {s['api_calls']:,}")
    print(f"  API errors:        {s['api_errors']:,}")
    print(f"  Wallets found:     {s['found']}")
    print(f"  Avg rate:          {s['mnemonics_per_hour']:,.0f} mnemonics/hour")
    print(f"{'=' * 70}")

if __name__ == "__main__":
    main()
