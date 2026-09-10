# Desynq — Modern Windows GUI & Runner for Zapret

[![Release](https://img.shields.io/github/v/release/StRonKEA/desynq?color=1a7a6d&label=Release)](https://github.com/StRonKEA/desynq/releases/latest)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20x64-blue)](https://github.com/StRonKEA/desynq)
[![Engine](https://img.shields.io/badge/Engine-Zapret%20%28winws2%29-orange)](https://github.com/bol-van/zapret)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Desynq** is an automated, measurement-driven DPI bypass and transparent DNS interceptor for Windows, powered by the **Zapret (`winws2`)** engine and **WinDivert**.

Instead of manually guessing complex Zapret command-line arguments (`--lua-desync`, `--split-pos`, `--dpi-desync`), Desynq automatically probes what your ISP actually blocks, tests 68 desynchronization techniques against your targets, ranks them by real handshake latency, and deploys the winning strategy as a background Windows Service.

---

## Key Features

- **Automated Zapret Strategy Discovery:** Tests 68 desynchronization candidates (multisplit, multidisorder, fakesplit, seqovl, fake) and selects the lowest-latency working method for your ISP.
- **Zero-Wait Instant Profiles:** Pre-configured 0s profiles for Turkcell Mobile, Vodafone Mobile, and TurkNet.
- **Transparent DoH Interceptor:** Kernel-level WinDivert engine intercepts outbound UDP port 53 and tunnels queries through encrypted Cloudflare DoH with a 0ms in-memory RAM cache.
- **QUIC / HTTP/3 Downgrade:** Silently drops UDP 443 to force browsers to fallback to TCP TLS, neutralizing UDP-based SNI blocking.
- **True "Install & Forget" Windows Service:** Runs as a native background service (`desynq-dpi` & `desynq-dns`). Automatically protects your entire PC on boot with zero GUI or tray window needed.
- **Pure Desktop GUI:** Modern, frameless, lightweight desktop UI with zero console flash (`-H windowsgui`).
- **Bilingual Interface:** Auto-detects system language (Turkish & English) with in-app switching.

---

## Download & Installation

### Option 1: 1-Click Installer (Recommended)
Download **`Desynq-Setup.exe`** from the [Latest Releases](https://github.com/StRonKEA/desynq/releases/latest).
- Installs to `C:\Program Files\Desynq` (safe from accidental file deletion).
- Creates Desktop and Start Menu shortcuts.
- Includes clean uninstaller that stops and removes background services cleanly.

### Option 2: Portable
Download **`Desynq-Portable.zip`** from [Releases](https://github.com/StRonKEA/desynq/releases/latest), extract anywhere, and run `desynq.exe`.

---

## Build from Source

### Requirements
- Windows 10 / 11 (64-bit)
- Go 1.22+
- Node.js 20+

### Build Command
Run the automated build script:
```bat
build.bat
```
Produces:
- `desynq.exe`: Standalone pure GUI application with built-in UAC engine.
- `Desynq-Setup.exe`: 1-Click NSIS installer.

---

## Search Tags & Keywords
`zapret` · `zapret-gui` · `zapret-windows` · `zapret-winws` · `dpi-bypass` · `goodbyedpi-alternative` · `windivert` · `dns-over-https` · `anti-censorship` · `turknet` · `turkcell` · `vodafone` · `discord-unblock`

---

## Acknowledgments
- **[Zapret](https://github.com/bol-van/zapret)** by @bol-van
- **[WinDivert](https://reqrypt.org/windivert.html)** packet interception library

## License
MIT License
