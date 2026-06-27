# Bitcoin Seed Phrase Balance Checker V.2 — High Performance Edition

Multi-threaded Bitcoin seed phrase balance checker optimized for high-core servers (100+ vCPU).

## Features

- BIP39 mnemonic generation (12/24 words)
- BIP44 (Legacy), BIP49 (Nested SegWit), BIP84 (Native SegWit) address derivation
- Concurrent API calls (blockstream.info + mempool.space)
- Configurable worker threads and concurrency
- Live stats (mnemonics/hour, API calls/second)
- Auto-save found wallets to `sukses.txt`
- Headless CLI (no GUI, perfect for servers)

## Install

```bash
pip install ecdsa mnemonic requests
```

## Usage

```bash
# Default: 80 workers, 50 concurrent API calls
python3 btc_seed_checker_hp.py

# Custom: 120 workers, 80 concurrent, 24-word mnemonic
python3 btc_seed_checker_hp.py -w 120 -c 80 -b 256

# Run in screen (survive SSH disconnect)
screen -S btc
python3 btc_seed_checker_hp.py -w 100 -c 60
```

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-w` | 80 | Worker threads (mnemonic generators) |
| `-c` | 50 | Concurrent API calls per batch |
| `-b` | 128 | 128=12 words, 256=24 words |
| `-s` | 0 | Derivation start index |
| `-e` | 20 | Derivation end index |
| `--delay` | 0.15 | API request delay (seconds) |

## Disclaimer

For legal, authorized, and educational purposes only.
