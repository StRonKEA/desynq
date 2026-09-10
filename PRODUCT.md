# dpi

## Product
Windows desktop tool that measures how the current ISP interferes with sites (DNS forgery vs TLS path kill), finds a working desync/DNS remedy for **this** link, and installs it with the smallest safe scope.

## Users
- Primary: a person whose ISP blocks sites; wants Discord/GitHub/etc. to open in a normal browser without thinking about strategies.
- Secondary: gamers who must not load a machine-wide packet driver (anti-cheat).
- Occasional: power users who already know `dpi.exe` but want a tray UI.

## Job to be done
1. Name a blocked site (or paste a URL).
2. Understand what the provider does (DNS vs path).
3. Choose scope: listed sites only vs whole machine.
4. Apply the fix once (UAC when needed).
5. Keep it healthy (refresh when CDN IPs move; re-search when DPI updates).

## Differentiator
Measures and ranks strategies on the live link instead of shipping a blind preset. Default capture is **targeted** so other apps never enter the driver.

## Platform
- Windows 10/11 x64 desktop (Wails + tray)
- Requires Administrator only for apply/pin/install paths
- Stack: Go CLI (`dpi.exe`) + Wails UI — **confirmed by repo**

## Capabilities the UI must expose
- Scope: whole machine vs listed sites
- Sites: add / remove / test / cover (apply filter)
- Actions: check, find/install strategy, refresh addresses, pin/unpin DNS, turn off
- Evidence: DNS · path · browser layers per site; coverage; stale pins
- First-run guide (optional skip)
- Elevated job progress without blocking the primary workspace

## Success
A non-expert can go from “site won’t open” to “opens” without reading the README, without the command log dominating the window, and without accidentally enabling machine-wide capture when they play anti-cheat games.

## Brand commitments
- The window is a **light** Fluent surface, not a dark VPN cockpit. Craft bar set by the user: Windows 11 Settings and other Fluent native apps.
- Copy is plain Turkish; state is a sentence, never a status code.

## Open decisions
- Whether Networks / Activity / Share from earlier design exploration ship in this pass

## Assumptions (from prior conversation — correct if wrong)
- Audience is mixed ages, not power users; UI copy is **Turkish** and plain
- Prefer clarity over console aesthetics; raw CLI output is secondary (collapsed “Ayrıntı”)
- Tray + background service remain the long-running home; the window is for setup and repair
- Shell: **Power + Mode** — site list exists only in “Sadece siteler”; machine-wide hides all site tools
