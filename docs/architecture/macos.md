# macOS

HyRoute for macOS reuses everything above the packet layer: the controller
(internal/app), the rules, groups, DNS policies, flows, the relay, the
tunnels manager and the Hysteria and Xray supervisors, and the window's
page. What differs is how packets reach the engine and how the program is
split into processes.

## Interception: utun instead of WinDivert

`internal/engine/engine_darwin.go` wires `engine.Core` to a utun device
(`tun_darwin.go`):

- The device gets `198.18.0.1` (peer `198.18.0.2`, RFC 2544 range) and,
  when the address can be assigned, `fdfe:dcba:9876::1`; MTU 9000.
- Routes `0.0.0.0/1` and `128.0.0.0/1` (`::/1` and `8000::/1` when the Mac
  has an IPv6 default route) send every destination without a more
  specific route into the device. The local network keeps its interface
  routes and never reaches it. The routes go with the device: if the
  service dies, the kernel destroys the device and traffic goes direct.
- Server addresses (`SetServerIPs`, called before Hysteria dials) get host
  routes through the physical default gateway, so the cores reach them
  outside the device. A server whose route could not be added still works:
  its packets reach the device and leave as HyRoute's own (the
  "hysteria" exclusion), only slower.

Every packet read from the device is outbound. A packet cannot go back to
the network unchanged (the routes would bring it back), so the core runs
with `Options.ReflectDirect`:

- TCP is reflected to the relay as on Windows, Direct included: a Direct
  flow gets a `nat.Direct` entry and the relay dials the destination itself
  from the physical interface (`IP_BOUND_IF`, `Engine.DialDirect`). The
  relay listens on the device's addresses only.
- A TCP segment of a connection the engine holds no state for (opened
  before the routes, or forgotten) is reset; the application reconnects
  through the engine.
- `Inject` of an outbound packet means "send it direct": UDP goes to
  `udpForwarder` (`udpfwd.go`), which keeps one socket on the physical
  interface per application socket and writes the replies into the device
  (endpoint-independent mapping). Other protocols (ICMP) are dropped.
- Tunnel UDP takes the core's SOCKS5 UDP ASSOCIATE path unchanged.
- DNS answers written into the device and queries read from it feed the
  DNS cache (`HandleDNS`), as the DNS sniff handle does on Windows.

`watchNetwork` follows the physical default route every 3 seconds: new
direct sockets bind to the new interface, the forwarder's sockets are
dropped, the server routes move to the new gateway.

## Attribution

There are no socket events. Each new flow asks the kernel's socket list
right away (`attrib.LookupOwner`: sysctl `net.inet.tcp.pcblist_n` and
`net.inet.udp.pcblist_n`, parsed by `ParsePCBList`). The PID is the socket's
effective PID when it works for another process (a system daemon's
connection for an application), else its last user. Process paths and the
process tree come from `kern.proc` and `kern.procargs2`
(`procinfo_darwin.go`). The system resolver mDNSResponder takes Dnscache's
place in the mandatory exclusions; `scutil --dns` gives the DNS servers and
local namespaces (`sysdns.ParseScutil`).

## Processes

`HyRoute.app` contains one universal binary (arm64 and amd64) and the cores.

- **The service** (`HyRoute --daemon`), root, a launchd daemon
  (`/Library/LaunchDaemons/com.hyroute.service.plist`, `RunAtLoad`,
  `KeepAlive`), runs from its own copy in
  `/Library/Application Support/HyRoute/bin` (root-owned: launchd runs it as
  root, so no user may be able to replace it). It holds what the Windows
  main process holds and serves the window on `/var/run/hyroute.sock` with
  the uirpc protocol; only root and members of group admin are served
  (`LOCAL_PEERCRED`). Its data is root's
  (`/var/root/Library/Application Support/HyRoute`, mode 0700): secrets are
  not sealed on macOS (`store/seal_other.go`), the folder protects them.
- **The window** (`HyRoute` without arguments, the user's process): Wails,
  the same page and `Bridge.Call` as the Windows window process. It asks the
  service's version (`ServiceVersion`); when the service is missing or of
  another version it runs `HyRoute --install-service` through the
  administrator prompt (osascript), which copies the bundle's binary and
  cores to the service folder and bootstraps the daemon.

`gui_shared.go` and the small `gui_*.go` files hold the page's calls common
to both systems; `gui_darwin.go` the macOS ones and stubs for what only
Windows has. The page asks `Platform()` and hides those parts.

## Not yet on macOS

The kill switch (pf), a menu bar icon, automatic updates of HyRoute and of
the cores, hyroutectl and the browser extension, ICMP through the engine.

## Building and tests

`scripts/build-macos.sh` builds the universal bundle (cgo, Wails tags
`desktop,production`), downloads the darwin cores pinned in
`build/deps.json` (`macos`) and checks their SHA-256, signs ad hoc and
zips it. The CI job `macos` runs the packages' tests, then
`TestTUNSession` as root: the runner is routed through a real utun while
curl and dig go through the tunnel (the SOCKS5 stub) and direct, and the
bundle is uploaded as an artifact. The release job `macos` publishes
`HyRoute-<version>-macos-universal.zip`.
