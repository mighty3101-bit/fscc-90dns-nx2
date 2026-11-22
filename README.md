# 90DNS Tester NX2

Native Nintendo Switch 2 DNS & connectivity verification homebrew built with [ounce-devkit / libounce](https://github.com/ouncebrew/ounce-devkit).

Author: **Reyn**

Works worldwide with **public 90DNS**, **self-hosted 90DNS**, **DNS-MITM (`hosts/default.txt`)**, **custom DNS/hotspot blockers**, and **kaiHEN** environments.

## Features
- **Dual DNS Resolver Check (Legacy + Async)**:
  - **Legacy**: Standard `gethostbyname` resolution.
  - **Async**: Firmware 23+ `sfdnsres` IPC (`QueryAddrInfoRequestWithOptions` / `FetchAddrInfoRequestWithOptions` / `CancelQuery`) with IPv4/IPv6 loopback & `0.0.0.0` verification.
- **Real Firmware Detection**: Queries `set:sys` directly (with kaiHEN homebrew session fallback) instead of relying on the spoofed `hbloader` version.
- **55 Domains Across 2 Clear Categories**:
  - **Pages 1-2 (Core Nintendo & Telemetry - 44 domains)**: Domains that **must** be blocked (`blocked` in green) on any 90DNS or DNS-MITM setup.
  - **Page 3 (Extended Regional & DoH - 11 domains)**: Extra Nintendo regional/CDN domains and DNS-over-HTTPS endpoints (`dns.google`, `cloudflare-dns.com`, `dns.quad9.net`). Standard public 90DNS does not block these by default; only strict/custom blockers do.
- **Page 4 (Connectivity & 90DNS HTTP Check - Port 80)**:
  - Tests `conntest.nintendowifi.net`, `ctest.cdn.nintendo.net`, `ctest.p01.ctest.srv.nintendo.net`, `api.p01.lp1.ctest.srv.nintendo.net` (`X-Organization: Nintendo`), and `90dns.test` (`X-Organization: LavaTech`).
  - Distinguishes a safe 90DNS/proxy HTTP responder from a real Nintendo leak or a pure `0.0.0.0`/`127.0.0.1` DNS-MITM block.
- **Full SD Log**: Writes detailed results and IPC status codes to `sdmc:/90dns-tester-nx2.log`.

## Installation
1. Download `90dns-tester-nx2-1.2.0.zip` (or `90dns-tester-nx2.nro`) from Releases / Actions.
2. Copy `90dns-tester-nx2.nro` to `/switch/90dns-tester-nx2/90dns-tester-nx2.nro` on your SD card.
3. Launch from Homebrew Menu.

## Controls
- **L / R** or **D-Pad Left / Right**: Switch pages (1-4)
- **X**: Re-run all tests
- **B**: Exit

## Status Reference
- `blocked` (Green): Resolved to `0.0.0.0`, `127.0.0.1`, `::`, or `::1` (safe).
- `unblocked` (Red): Resolved to a non-blocked IP (leak if in Core Nintendo & Telemetry).
- `unresolved` / `timeout` (Yellow): Domain could not resolve or timed out (not reaching Nintendo, though `blocked` is preferred for Core domains).
- `event-wait` (Yellow): Async `sfdnsres` event did not signal within 2.5s.
- `N/A` / `error` (Yellow): Async `sfdnsres` command unavailable or IPC error (check `sdmc:/90dns-tester-nx2.log`).
