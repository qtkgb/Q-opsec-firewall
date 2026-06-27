//! firewall_core — the shared, memory-safe datapath for the Q opsec firewall.
//!
//! Phase 1b: real forwarding. No-root means no raw sockets, so we cannot just
//! re-inject packets — we must TERMINATE each transport locally and RE-ORIGINATE it
//! through OS sockets that VpnService.protect()s (so they bypass our own tun instead
//! of looping). `netstack-smoltcp` drives a smoltcp userspace TCP/IP stack over the tun
//! and hands us, per flow, a `TcpStream` / UDP datagrams addressed to the *real*
//! destination; we relay each to a protected OS socket. Allow-by-default; the kill
//! switch (mode 2) refuses new flows.
//!
//! JNI symbol convention: `Java_<pkg with _>_<Class>_<method>`.
//! Kotlin side = `com.qopsec.firewall.vpn.NativeBridge`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use jni::objects::{GlobalRef, JClass, JObject, JValue};
use jni::sys::{jint, jlong, jstring};
use jni::{JNIEnv, JavaVM};

use netstack_smoltcp::udp::{ReadHalf as UdpReadHalf, UdpMsg, WriteHalf as UdpWriteHalf};
use netstack_smoltcp::{StackBuilder, TcpStream};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::{mpsc, oneshot, Notify};

const MTU: usize = 1500;
const UDP_IDLE_SECS: u64 = 60;
const PROTO_TCP: jint = 6;
const PROTO_UDP: jint = 17;
const PORT_HTTPS: u16 = 443;
/// How long to wait for the TLS ClientHello before relaying a :443 flow without SNI.
const SNI_PEEK_SECS: u64 = 2;
/// Fail-open watchdog (engine_main): check interval, the per-window ingress packets that count as
/// "traffic is flowing", and how many consecutive windows of (ingress flowing, egress frozen) before
/// we declare the datapath wedged and tear the tunnel down.
const WATCHDOG_SECS: u64 = 3;
const WATCHDOG_MIN_INGRESS: u64 = 200;
const WATCHDOG_STRIKES: u32 = 3;

// Verdicts returned by the Kotlin matcher (NativeBridge.decideFlow).
const VERDICT_ALLOW: i32 = 0;
const VERDICT_DENY: i32 = 1;
const VERDICT_PENDING: i32 = 2; // ask-mode: hold the flow until the user answers

// How long a held (pending) TCP flow waits for a verdict before defaulting to deny.
const PENDING_TIMEOUT: Duration = Duration::from_secs(30);

// Engine modes — must match NativeBridge / state machine on the Kotlin side.
const MODE_FILTER: u8 = 1; // allow-by-default forwarding (Phase 1b)
const MODE_DENY: u8 = 2; // kill switch: refuse new flows

// Cached once at first nativeStart, from a Java thread (so the app classloader is in
// scope). Reused on tokio threads, which otherwise can't `find_class` app classes.
static JVM: OnceLock<JavaVM> = OnceLock::new();
static BRIDGE_CLASS: OnceLock<GlobalRef> = OnceLock::new();
static FLOW_ID: AtomicU64 = AtomicU64::new(1);
/// Whether to forward IPv6 (set from Kotlin via nativeSetIpv6 based on real v6 egress). When false
/// the netstack drops v6 at ingress so dual-stack apps fall back to IPv4 (see the filter comment).
static IPV6_FWD: AtomicBool = AtomicBool::new(false);

/// Datapath liveness counters for the fail-open watchdog (see engine_main). If the netstack wedges
/// under sustained load (smoltcp stuck "device exhausted", or the egress task dies) the tunnel would
/// stay up but pass no traffic -> internet blackhole that survives closing the app (foreground
/// service). The watchdog notices ingress flowing with egress flat and tears the tunnel down instead.
static INGRESS_PKTS: AtomicU64 = AtomicU64::new(0);
static EGRESS_PKTS: AtomicU64 = AtomicU64::new(0);

/// Raw tun fd, shared so nativeStop (and the fail-open watchdog teardown) can close it DIRECTLY and
/// immediately — bringing the OS VPN interface down and restoring internet the instant Stop is
/// tapped, without waiting for the engine threads to unwind. `Tun` does NOT own the fd (it wraps a
/// non-closing `RawTun`); this guarded swap is the single closer, so it's safe to call from both the
/// stop path and `Tun::drop` (whoever runs first closes; the other no-ops).
static TUN_FD: AtomicI32 = AtomicI32::new(-1);

/// Close the tun fd exactly once (idempotent). Brings the VPN interface down -> traffic flows
/// normally again, and makes the engine's read/write tasks error out so the runtime can unwind.
fn close_tun_fd() {
    let fd = TUN_FD.swap(-1, Ordering::SeqCst);
    if fd >= 0 {
        unsafe { libc::close(fd) };
        log::info!("Tun fd {fd} closed (interface down)");
    }
}

/// Active = relaying (re-eval tears it down if now denied). Pending = held awaiting a
/// verdict (re-eval wakes it to re-decide).
#[derive(Clone, Copy, PartialEq)]
enum FlowKind {
    Active,
    Pending,
}

/// A tracked flow. `cancel` notified -> active flow tears down, or pending flow re-decides.
/// Each flow task self-registers/-removes.
struct FlowRec {
    kind: FlowKind,
    proto: jint,
    src: SocketAddr,
    dst: SocketAddr,
    cancel: Arc<Notify>,
}
type FlowRegistry = Arc<Mutex<HashMap<u64, FlowRec>>>;

/// Removes a flow from the registry when its task ends (for any reason).
struct FlowGuard {
    id: u64,
    reg: FlowRegistry,
}
impl Drop for FlowGuard {
    fn drop(&mut self) {
        if let Ok(mut m) = self.reg.lock() {
            m.remove(&self.id);
        }
    }
}

/// Opaque engine handle returned to Kotlin as a jlong.
struct Engine {
    stop_tx: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    mode: Arc<AtomicU8>,
    registry: FlowRegistry,
}

/// Re-evaluate tracked flows after a rule change / kill switch. Active flows that are now
/// denied get torn down; pending (held) flows get woken to re-decide themselves.
fn reevaluate(registry: &FlowRegistry, mode: &Arc<AtomicU8>) {
    let kill = mode.load(Ordering::Relaxed) == MODE_DENY;
    let entries: Vec<(FlowKind, jint, SocketAddr, SocketAddr, Arc<Notify>)> = match registry.lock() {
        Ok(m) => m
            .values()
            .map(|r| (r.kind, r.proto, r.src, r.dst, r.cancel.clone()))
            .collect(),
        Err(_) => return,
    };
    for (kind, proto, src, dst, cancel) in entries {
        match kind {
            // Pending flows always re-decide on wake (handles allow/deny/kill themselves).
            FlowKind::Pending => cancel.notify_one(),
            FlowKind::Active => {
                if kill || decide_flow(proto, src, dst) == VERDICT_DENY {
                    cancel.notify_one();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JNI exports
// ---------------------------------------------------------------------------

/// Returns the core version — confirms the native library loaded and JNI works.
#[no_mangle]
pub extern "system" fn Java_com_qopsec_firewall_vpn_NativeBridge_nativeVersion<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let s = format!("firewall-core {} (smoltcp)", env!("CARGO_PKG_VERSION"));
    match env.new_string(s) {
        Ok(js) => js.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Take ownership of the tun fd and start the datapath. Returns an opaque engine handle (0 = error).
/// Kotlin must pass a *detached* fd (ParcelFileDescriptor.detachFd) — we close it on stop.
#[no_mangle]
pub extern "system" fn Java_com_qopsec_firewall_vpn_NativeBridge_nativeStart<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    tun_fd: jint,
    log_level: jint,
) -> jlong {
    init_log(log_level as i32);

    // Cache JVM + the NativeBridge class (must happen on this Java thread).
    if let Ok(vm) = env.get_java_vm() {
        let _ = JVM.set(vm);
    }
    if BRIDGE_CLASS.get().is_none() {
        match env
            .find_class("com/qopsec/firewall/vpn/NativeBridge")
            .and_then(|c| env.new_global_ref(c))
        {
            Ok(g) => {
                let _ = BRIDGE_CLASS.set(g);
            }
            Err(e) => log::error!("cache NativeBridge class failed: {e}"),
        }
    }

    let mode = Arc::new(AtomicU8::new(MODE_FILTER));
    let registry: FlowRegistry = Arc::new(Mutex::new(HashMap::new()));
    let (stop_tx, stop_rx) = oneshot::channel();
    let fd = tun_fd as RawFd;
    let engine_mode = mode.clone();
    let engine_registry = registry.clone();

    let thread = std::thread::Builder::new()
        .name("fw-core".into())
        .spawn(move || engine_main(fd, engine_mode, engine_registry, stop_rx))
        .ok();

    if thread.is_none() {
        log::error!("failed to spawn engine thread");
        return 0;
    }

    let engine = Box::new(Engine {
        stop_tx: Some(stop_tx),
        thread,
        mode,
        registry,
    });
    log::info!("firewall_core started on tun fd {fd}");
    Box::into_raw(engine) as jlong
}

/// Change the core's log verbosity live (Settings → Diagnostics): 0 off / 1 info / 2 debug.
#[no_mangle]
pub extern "system" fn Java_com_qopsec_firewall_vpn_NativeBridge_nativeSetLogLevel<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    level: jint,
) {
    set_log_level(level as i32);
}

/// Stop the datapath and release resources for the given handle.
#[no_mangle]
pub extern "system" fn Java_com_qopsec_firewall_vpn_NativeBridge_nativeStop<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    log::info!("nativeStop: ENTER handle={handle}");
    let mut engine = unsafe { Box::from_raw(handle as *mut Engine) };
    // STEP 1 — bring the interface DOWN immediately. This restores normal internet the instant Stop
    // is tapped, regardless of whether the engine threads are wedged under load, and unblocks the
    // tun read/write tasks so the runtime can unwind. This is the fix for "Stop but traffic still
    // blocked / app ANRs": teardown no longer depends on a possibly-stuck engine.
    close_tun_fd();
    // STEP 2 — ask the engine to stop; engine_main does a BOUNDED shutdown_timeout, so the join below
    // returns promptly even if a worker is spinning. (Kotlin also runs nativeStop off the main thread
    // as belt-and-suspenders.)
    if let Some(tx) = engine.stop_tx.take() {
        let _ = tx.send(());
    }
    if let Some(t) = engine.thread.take() {
        log::info!("nativeStop: joining engine thread...");
        let _ = t.join();
        log::info!("nativeStop: engine thread JOINED");
    }
    log::info!("firewall_core stopped (nativeStop RETURNING)");
}

/// Set engine mode: 1 = Filter (allow-by-default forwarding), 2 = DenyAll (kill switch).
#[no_mangle]
pub extern "system" fn Java_com_qopsec_firewall_vpn_NativeBridge_nativeSetMode<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    mode: jint,
) {
    if handle == 0 {
        return;
    }
    let engine = unsafe { &*(handle as *const Engine) };
    engine.mode.store(mode as u8, Ordering::Relaxed);
    log::info!("firewall_core mode -> {mode}");
    // Apply to live flows too (kill switch tears down everything; un-kill is a no-op here).
    reevaluate(&engine.registry, &engine.mode);
}

/// Re-evaluate active flows against the current rules — called by Kotlin after a rule change
/// so reversals are instant (live connections that are now denied get torn down).
#[no_mangle]
pub extern "system" fn Java_com_qopsec_firewall_vpn_NativeBridge_nativeReevaluate<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    let engine = unsafe { &*(handle as *const Engine) };
    reevaluate(&engine.registry, &engine.mode);
}

/// Enable/disable IPv6 forwarding (Kotlin sets this from real v6 egress detection). Affects new
/// flows: when disabled the netstack drops v6 at ingress so apps fall back to IPv4.
#[no_mangle]
pub extern "system" fn Java_com_qopsec_firewall_vpn_NativeBridge_nativeSetIpv6<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    enabled: jni::sys::jboolean,
) {
    IPV6_FWD.store(enabled != 0, Ordering::Relaxed);
    log::info!("firewall_core ipv6 forwarding -> {}", enabled != 0);
}

// ---------------------------------------------------------------------------
// Engine: tokio runtime + netstack + relays
// ---------------------------------------------------------------------------

fn engine_main(
    tun_fd: RawFd,
    mode: Arc<AtomicU8>,
    registry: FlowRegistry,
    stop_rx: oneshot::Receiver<()>,
) {
    // MULTI-THREADED runtime (was new_current_thread). Under a sustained high-throughput upload the
    // netstack (smoltcp) can momentarily run out of TX tokens ("device exhausted") and its interface
    // runner busy-polls until the egress (netstack->tun) task drains it. On a SINGLE-threaded executor
    // the spinning runner starves that very drain task -> livelock: the upload stalls and a CPU is
    // pegged (and at FULL diagnostics this also floods logcat ~170k lines/s -> ANR). With >1 worker the
    // drain task runs concurrently with the runner, so the exhausted condition clears and throughput
    // holds. Kept small (2 workers) to break the livelock without spawning a thread per core (battery).
    // JNI is fine on any worker: the protect/decide/dns callbacks attach_current_thread() per call, and
    // shared state is Arc<Mutex>/atomics.
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("tokio runtime build failed: {e}");
            unsafe { libc::close(tun_fd) };
            return;
        }
    };

    log::info!("engine_main: runtime built (multi-thread); attaching to JVM");
    // Attach the block_on thread to the JVM. Worker threads attach themselves per callback
    // (attach_current_thread in protect_fd/decide_flow/report_dns/is_blocked_host).
    if let Some(vm) = JVM.get() {
        let _ = vm.attach_current_thread_as_daemon();
    }

    log::info!("engine_main: entering block_on");
    rt.block_on(async move {
        let tun = match Tun::new(tun_fd) {
            Ok(t) => Arc::new(t),
            Err(e) => {
                log::error!("tun setup failed: {e}");
                return;
            }
        };

        let (stack, runner, udp, tcp) = match StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(true)
            .mtu(MTU)
            // IPv6 forwarding is GATED on real v6 egress (IPV6_FWD, set from Kotlin). We always
            // CAPTURE IPv6 (the tun keeps a ::/0 route, so v6 can't leak around the VPN), but when
            // IPV6_FWD is false we drop it at the netstack ingress instead of locally completing the
            // handshake. Otherwise, on networks without real IPv6 egress (e.g. the emulator), a
            // dual-stack app's happy-eyeballs would "connect" to our instant local SYN-ACK, then we'd
            // fail the upstream v6 connect and close it — ERR_CONNECTION_CLOSED with no IPv4 fallback.
            // Dropping v6 when there's no v6 egress makes apps fall back to IPv4 cleanly.
            .add_ip_filter_fn(|_src, dst| dst.is_ipv4() || IPV6_FWD.load(Ordering::Relaxed))
            .build()
        {
            Ok(parts) => parts,
            Err(e) => {
                log::error!("netstack build failed: {e}");
                return;
            }
        };

        let (mut stack_sink, mut stack_stream) = stack.split();

        // smoltcp interface driver.
        if let Some(runner) = runner {
            tokio::spawn(runner);
        }

        // Egress: netstack -> tun.
        {
            let tun = tun.clone();
            tokio::spawn(async move {
                while let Some(pkt) = stack_stream.next().await {
                    match pkt {
                        Ok(pkt) => {
                            if let Err(e) = tun.write_packet(&pkt).await {
                                log::error!("tun write: {e}");
                                break;
                            }
                            EGRESS_PKTS.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => log::error!("netstack egress: {e}"),
                    }
                }
                log::info!("egress task (netstack->tun) exiting");
            });
        }

        // Ingress: tun -> netstack.
        {
            let tun = tun.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65_535];
                loop {
                    match tun.read_packet(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stack_sink.send(buf[..n].to_vec()).await.is_err() {
                                break;
                            }
                            INGRESS_PKTS.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            log::error!("tun read: {e}");
                            break;
                        }
                    }
                }
                log::info!("ingress task (tun->netstack) exiting");
            });
        }

        // TCP: accept terminated connections, relay to protected OS sockets.
        if let Some(mut tcp) = tcp {
            let mode = mode.clone();
            let registry = registry.clone();
            tokio::spawn(async move {
                while let Some((stream, src, dst)) = tcp.next().await {
                    let id = FLOW_ID.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(handle_tcp(id, stream, src, dst, mode.clone(), registry.clone()));
                }
                log::info!("tcp accept task exiting");
            });
        }

        // UDP: per-flow relay through protected OS sockets; replies fed back via one writer.
        if let Some(udp) = udp {
            let (udp_read, udp_write) = udp.split();
            let (reply_tx, reply_rx) = mpsc::channel::<UdpMsg>(256);
            tokio::spawn(udp_writer(udp_write, reply_rx));
            tokio::spawn(udp_dispatch(udp_read, reply_tx, mode.clone(), registry.clone()));
        }

        // FAIL-OPEN WATCHDOG. If the datapath wedges under load (smoltcp stuck "device exhausted",
        // egress task dead) the tunnel stays up but forwards nothing -> internet blackhole that
        // survives closing the app (foreground service). Detect it as: packets keep arriving from the
        // tun (ingress advancing) while NOTHING goes back out (egress flat) across two windows, then
        // notify Kotlin to tear the tunnel down (restore internet, unfiltered). Asymmetric by design:
        // a pure download has high egress, a pure upload still emits ACKs (egress != 0), and idle has
        // ~0 ingress — so only a true wedge (ingress flowing, egress frozen) trips it.
        tokio::spawn(async move {
            let mut last_in = INGRESS_PKTS.load(Ordering::Relaxed);
            let mut last_eg = EGRESS_PKTS.load(Ordering::Relaxed);
            let mut strikes = 0u32;
            loop {
                tokio::time::sleep(Duration::from_secs(WATCHDOG_SECS)).await;
                let now_in = INGRESS_PKTS.load(Ordering::Relaxed);
                let now_eg = EGRESS_PKTS.load(Ordering::Relaxed);
                let stalled = now_in.wrapping_sub(last_in) >= WATCHDOG_MIN_INGRESS && now_eg == last_eg;
                last_in = now_in;
                last_eg = now_eg;
                if stalled {
                    strikes += 1;
                    log::warn!("watchdog: datapath stall suspected ({strikes}/{WATCHDOG_STRIKES})");
                    if strikes >= WATCHDOG_STRIKES {
                        log::error!("watchdog: datapath wedged -> failing open (tearing tunnel down)");
                        report_stall();
                        break;
                    }
                } else {
                    strikes = 0;
                }
            }
        });

        log::info!("engine_main: datapath running; awaiting stop signal");
        let _ = stop_rx.await;
        log::info!("engine loop exiting (stop signal received; block_on async block returning)");
    });
    log::info!("engine_main: block_on returned; shutting down runtime");
    // Make sure the interface is down even if a task is wedged (e.g. the smoltcp runner busy-spinning
    // on "device exhausted" under load won't drop the Tun on its own).
    close_tun_fd();
    // BOUNDED shutdown: a busy-spinning async task has no await point to cancel at, so a plain
    // drop(rt) could block this thread (-> nativeStop's join -> main-thread ANR). shutdown_timeout
    // forces the runtime down within the budget so engine_main always returns promptly.
    rt.shutdown_timeout(Duration::from_millis(500));
    log::info!("engine_main: runtime shut down; engine_main RETURNING (thread will now exit)");
}

// ---------------------------------------------------------------------------
// TCP relay
// ---------------------------------------------------------------------------

async fn handle_tcp(
    id: u64,
    mut inbound: TcpStream,
    src: SocketAddr,
    dst: SocketAddr,
    mode: Arc<AtomicU8>,
    registry: FlowRegistry,
) {
    let cancel = Arc::new(Notify::new());
    let _guard = FlowGuard { id, reg: registry.clone() };

    // SNI peek (HTTPS): read the TLS ClientHello *before* deciding, so we recover the
    // destination hostname even when DNS was encrypted (DoH/DoT) or the IP was cached /
    // IP-literal. The host is published to the DNS cache so the Kotlin matcher's host &
    // ad-block rules can see it; the bytes are buffered and replayed to the upstream socket
    // once we connect. Best-effort: a slow or non-TLS client just proceeds without SNI.
    let mut prebuf: Vec<u8> = Vec::new();
    if dst.port() == PORT_HTTPS && mode.load(Ordering::Relaxed) != MODE_DENY {
        let mut buf = vec![0u8; 4096];
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(SNI_PEEK_SECS), inbound.read(&mut buf)).await
        {
            if n > 0 {
                buf.truncate(n);
                if let Some(sni) = parse_tls_sni(&buf) {
                    report_dns(&sni, &dst.ip().to_string());
                    log::debug!("tcp {dst} sni {sni}");
                }
                prebuf = buf;
            }
        }
    }

    // Decide, HOLDING while the verdict is pending (ask-mode). The connection's handshake
    // is already complete (netstack), so the app just waits for a response until we connect
    // upstream (allow), close (deny), or time out. Re-evaluation (user answered the prompt)
    // wakes us via `cancel` to re-decide.
    let verdict = loop {
        let v = if mode.load(Ordering::Relaxed) == MODE_DENY {
            VERDICT_DENY
        } else {
            decide_flow(PROTO_TCP, src, dst)
        };
        if v != VERDICT_PENDING {
            break v;
        }
        if let Ok(mut m) = registry.lock() {
            m.insert(
                id,
                FlowRec { kind: FlowKind::Pending, proto: PROTO_TCP, src, dst, cancel: cancel.clone() },
            );
        }
        let woke = tokio::select! {
            _ = cancel.notified() => true,
            _ = tokio::time::sleep(PENDING_TIMEOUT) => false,
        };
        if !woke {
            log::debug!("tcp {dst} pending timed out -> deny");
            break VERDICT_DENY;
        }
        // looped: re-decide with the (possibly) updated rules
    };

    if verdict == VERDICT_DENY {
        log::debug!("tcp {dst} denied");
        return; // guard removes from registry; dropping `inbound` closes the connection
    }

    let sock = match dst {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    };
    let sock = match sock {
        Ok(s) => s,
        Err(e) => {
            log::error!("tcp socket {dst}: {e}");
            return;
        }
    };

    // Must protect BEFORE connect, or the SYN routes back into our own tun.
    if !protect_fd(sock.as_raw_fd()) {
        log::error!("protect failed for tcp {dst}");
        return;
    }

    let mut outbound = match sock.connect(dst).await {
        Ok(s) => s,
        Err(e) => {
            log::warn!("tcp connect {dst}: {e}");
            return;
        }
    };

    // Replay the bytes we peeked for SNI (the ClientHello) before relaying the rest.
    if !prebuf.is_empty() {
        if let Err(e) = outbound.write_all(&prebuf).await {
            log::debug!("tcp {dst} prebuf write: {e}");
            return;
        }
    }

    // Allowed + connected: register Active so a rule change / kill switch can tear it down.
    if let Ok(mut m) = registry.lock() {
        m.insert(
            id,
            FlowRec { kind: FlowKind::Active, proto: PROTO_TCP, src, dst, cancel: cancel.clone() },
        );
    }

    tokio::select! {
        r = tokio::io::copy_bidirectional(&mut inbound, &mut outbound) => {
            if let Err(e) = r {
                log::debug!("tcp relay {dst} ended: {e}");
            }
        }
        _ = cancel.notified() => {
            log::debug!("tcp {dst} torn down by re-evaluation");
        }
    }
}

// ---------------------------------------------------------------------------
// UDP relay
// ---------------------------------------------------------------------------

/// Routes outbound datagrams to per-flow tasks, creating one on first sight of a flow.
async fn udp_dispatch(
    mut reader: UdpReadHalf,
    reply_tx: mpsc::Sender<UdpMsg>,
    mode: Arc<AtomicU8>,
    registry: FlowRegistry,
) {
    let mut flows: HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>> = HashMap::new();

    while let Some((payload, src, dst)) = reader.next().await {
        if mode.load(Ordering::Relaxed) == MODE_DENY {
            continue;
        }

        // Ad/tracker DNS sinkhole: a blocked query name gets a forged NXDOMAIN reply and is
        // never relayed upstream — so the ad/tracker domain simply doesn't resolve.
        if dst.port() == 53 {
            if let Some(qname) = parse_dns_question(&payload) {
                if is_blocked_host(&qname) {
                    if let Some(resp) = build_nxdomain(&payload) {
                        let _ = reply_tx.send((resp, dst, src)).await;
                    }
                    log::debug!("dns sinkholed {qname}");
                    continue;
                }
            }
        }

        let key = (src, dst);
        let payload = if let Some(tx) = flows.get(&key) {
            match tx.send(payload).await {
                Ok(()) => continue,
                // Flow task ended; recover the datagram and recreate below.
                Err(e) => {
                    flows.remove(&key);
                    e.0
                }
            }
        } else {
            payload
        };

        // New flow — ask the matcher. (Kill switch handled at the top of the loop.)
        // UDP isn't held: deny OR pending drops the datagram; the app retries (DNS/QUIC do),
        // and once the user allows the app the next datagram creates the relay.
        if decide_flow(PROTO_UDP, src, dst) != VERDICT_ALLOW {
            log::debug!("udp {dst} not allowed");
            continue;
        }
        match UdpFlow::new(src, dst).await {
            Ok((tx, flow)) => {
                let id = FLOW_ID.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(flow.run(id, registry.clone(), reply_tx.clone()));
                let _ = tx.send(payload).await;
                flows.insert(key, tx);
            }
            Err(e) => log::warn!("udp flow {dst}: {e}"),
        }
    }
}

/// One outbound UDP flow over a protected OS socket.
struct UdpFlow {
    sock: UdpSocket,
    src: SocketAddr, // the app endpoint
    dst: SocketAddr, // the real server
    rx: mpsc::Receiver<Vec<u8>>,
}

impl UdpFlow {
    async fn new(
        src: SocketAddr,
        dst: SocketAddr,
    ) -> std::io::Result<(mpsc::Sender<Vec<u8>>, Self)> {
        let bind: SocketAddr = if dst.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = UdpSocket::bind(bind).await?;
        if !protect_fd(sock.as_raw_fd()) {
            return Err(std::io::Error::other("protect failed"));
        }
        sock.connect(dst).await?;
        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
        Ok((tx, Self { sock, src, dst, rx }))
    }

    async fn run(mut self, id: u64, registry: FlowRegistry, reply_tx: mpsc::Sender<UdpMsg>) {
        let cancel = Arc::new(Notify::new());
        let _guard = FlowGuard { id, reg: registry.clone() };
        if let Ok(mut m) = registry.lock() {
            m.insert(
                id,
                FlowRec {
                    kind: FlowKind::Active,
                    proto: PROTO_UDP,
                    src: self.src,
                    dst: self.dst,
                    cancel: cancel.clone(),
                },
            );
        }
        let mut buf = vec![0u8; 65_535];
        loop {
            tokio::select! {
                _ = cancel.notified() => {
                    log::debug!("udp {} torn down by re-evaluation", self.dst);
                    break;
                }
                outbound = self.rx.recv() => match outbound {
                    Some(p) => { let _ = self.sock.send(&p).await; }
                    None => break,
                },
                resp = self.sock.recv(&mut buf) => match resp {
                    // Reply must look like it came FROM the server TO the app.
                    Ok(n) => {
                        // Learn IP -> hostname from DNS answers so host rules can match.
                        if self.dst.port() == 53 {
                            for (host, ip) in parse_dns_answers(&buf[..n]) {
                                report_dns(&host, &ip.to_string());
                            }
                            // CNAME-uncloak: a tracker can hide behind a first-party alias
                            // (metrics.example.com CNAME -> tracker.adnetwork.com). The bare
                            // QNAME isn't on a list, so the question-path sinkhole misses it;
                            // the response reveals the chain. If any CNAME target is blocked,
                            // forge NXDOMAIN instead of relaying the real (cloaked) answer.
                            if let Some(t) =
                                dns_answer_cnames(&buf[..n]).into_iter().find(|t| is_blocked_host(t))
                            {
                                if let Some(resp) = build_nxdomain(&buf[..n]) {
                                    log::debug!("dns cname-uncloaked {t}");
                                    let _ = reply_tx.send((resp, self.dst, self.src)).await;
                                    continue; // drop the cloaked answer
                                }
                            }
                        }
                        if reply_tx.send((buf[..n].to_vec(), self.dst, self.src)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
                _ = tokio::time::sleep(Duration::from_secs(UDP_IDLE_SECS)) => break,
            }
        }
    }
}

/// Single owner of the netstack UDP write half; serializes replies back into the tun.
async fn udp_writer(mut writer: UdpWriteHalf, mut rx: mpsc::Receiver<UdpMsg>) {
    while let Some(msg) = rx.recv().await {
        if writer.send(msg).await.is_err() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// tun device (async over the raw fd)
// ---------------------------------------------------------------------------

/// Non-owning fd wrapper: gives AsyncFd an AsRawFd to register with epoll WITHOUT closing the fd on
/// drop. The fd is closed exactly once via `close_tun_fd()` (from the stop path or `Tun::drop`), so
/// teardown is deterministic and never double-closes.
struct RawTun(RawFd);
impl AsRawFd for RawTun {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

struct Tun {
    fd: AsyncFd<RawTun>,
}

impl Drop for Tun {
    fn drop(&mut self) {
        // Normal-path closer (the stop path may have already closed it; close_tun_fd is idempotent).
        log::info!("Tun::drop");
        close_tun_fd();
    }
}

impl Tun {
    fn new(raw: RawFd) -> std::io::Result<Self> {
        // O_NONBLOCK so AsyncFd readiness works.
        unsafe {
            let flags = libc::fcntl(raw, libc::F_GETFL);
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        TUN_FD.store(raw, Ordering::SeqCst);
        Ok(Self {
            fd: AsyncFd::new(RawTun(raw))?,
        })
    }

    async fn read_packet(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }

    async fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let n =
                    unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JNI callbacks into Kotlin (run on tokio threads -> attach + cached class)
// ---------------------------------------------------------------------------

/// Calls `VpnService.protect(fd)` via `NativeBridge.protectFd`. Must succeed before we
/// send any traffic on an OS socket, else it loops back into our own tun.
fn protect_fd(fd: RawFd) -> bool {
    let (Some(vm), Some(class_ref)) = (JVM.get(), BRIDGE_CLASS.get()) else {
        return false;
    };
    let mut env = match vm.attach_current_thread_as_daemon() {
        Ok(e) => e,
        Err(e) => {
            log::error!("attach (protect): {e}");
            return false;
        }
    };
    let class = unsafe { JClass::from_raw(class_ref.as_raw()) };
    let res = env
        .call_static_method(class, "protectFd", "(I)Z", &[JValue::Int(fd as jint)])
        .and_then(|v| v.z());
    let _ = env.exception_clear();
    res.unwrap_or(false)
}

/// Asks the Kotlin rule matcher for a verdict on a new flow (`NativeBridge.decideFlow`).
/// Also drives the live capture list + conn history on the Kotlin side. Fail-open (ALLOW)
/// if the bridge isn't reachable, so loss of the callback never silently blocks traffic.
fn decide_flow(proto: jint, src: SocketAddr, dst: SocketAddr) -> i32 {
    let (Some(vm), Some(class_ref)) = (JVM.get(), BRIDGE_CLASS.get()) else {
        return VERDICT_ALLOW;
    };
    let mut env = match vm.attach_current_thread_as_daemon() {
        Ok(e) => e,
        Err(_) => return VERDICT_ALLOW,
    };
    let class = unsafe { JClass::from_raw(class_ref.as_raw()) };

    let (Ok(src_ip), Ok(dst_ip)) = (
        env.new_string(src.ip().to_string()),
        env.new_string(dst.ip().to_string()),
    ) else {
        return VERDICT_ALLOW;
    };
    let src_obj: JObject = src_ip.into();
    let dst_obj: JObject = dst_ip.into();

    let res = env
        .call_static_method(
            class,
            "decideFlow",
            "(ILjava/lang/String;ILjava/lang/String;I)I",
            &[
                JValue::Int(proto),
                JValue::Object(&src_obj),
                JValue::Int(src.port() as jint),
                JValue::Object(&dst_obj),
                JValue::Int(dst.port() as jint),
            ],
        )
        .and_then(|v| v.i());
    let _ = env.exception_clear();
    res.unwrap_or(VERDICT_ALLOW)
}

/// Reports a learned DNS mapping (`host` -> `ip`) to Kotlin (`NativeBridge.onDns`).
fn report_dns(host: &str, ip: &str) {
    let (Some(vm), Some(class_ref)) = (JVM.get(), BRIDGE_CLASS.get()) else {
        return;
    };
    let mut env = match vm.attach_current_thread_as_daemon() {
        Ok(e) => e,
        Err(_) => return,
    };
    let class = unsafe { JClass::from_raw(class_ref.as_raw()) };
    let (Ok(h), Ok(i)) = (env.new_string(host), env.new_string(ip)) else {
        return;
    };
    let h_obj: JObject = h.into();
    let i_obj: JObject = i.into();
    let _ = env.call_static_method(
        class,
        "onDns",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        &[JValue::Object(&h_obj), JValue::Object(&i_obj)],
    );
    let _ = env.exception_clear();
}

/// Asks Kotlin (`NativeBridge.isBlockedHost`) whether a DNS query name is an ad/tracker to sinkhole.
fn is_blocked_host(name: &str) -> bool {
    let (Some(vm), Some(class_ref)) = (JVM.get(), BRIDGE_CLASS.get()) else {
        return false;
    };
    let mut env = match vm.attach_current_thread_as_daemon() {
        Ok(e) => e,
        Err(_) => return false,
    };
    let class = unsafe { JClass::from_raw(class_ref.as_raw()) };
    let Ok(s) = env.new_string(name) else {
        return false;
    };
    let s_obj: JObject = s.into();
    let res = env
        .call_static_method(class, "isBlockedHost", "(Ljava/lang/String;)Z", &[JValue::Object(&s_obj)])
        .and_then(|v| v.z());
    let _ = env.exception_clear();
    res.unwrap_or(false)
}

/// Tell Kotlin (`NativeBridge.onStall`) the datapath has wedged so it can fail open (tear the tunnel
/// down -> restore internet). Called from the watchdog on a tokio worker thread.
fn report_stall() {
    let (Some(vm), Some(class_ref)) = (JVM.get(), BRIDGE_CLASS.get()) else {
        return;
    };
    let mut env = match vm.attach_current_thread_as_daemon() {
        Ok(e) => e,
        Err(_) => return,
    };
    let class = unsafe { JClass::from_raw(class_ref.as_raw()) };
    let _ = env.call_static_method(class, "onStall", "()V", &[]);
    let _ = env.exception_clear();
}

/// Parse a DNS *query* and return the first question's name (None if not a query / malformed).
fn parse_dns_question(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 || buf[2] & 0x80 != 0 {
        return None; // too short, or it's a response (QR=1)
    }
    if u16::from_be_bytes([buf[4], buf[5]]) == 0 {
        return None; // no question
    }
    read_dns_name(buf, 12).map(|(name, _)| name)
}

/// Build an NXDOMAIN response echoing the query's header+question (sinkhole reply).
fn build_nxdomain(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut r = query.to_vec();
    r[2] |= 0x80;            // QR = response
    r[3] = 0x80 | 0x03;      // RA=1, RCODE=3 (NXDOMAIN)
    r[6] = 0; r[7] = 0;      // ANCOUNT = 0
    r[8] = 0; r[9] = 0;      // NSCOUNT = 0
    r[10] = 0; r[11] = 0;    // ARCOUNT = 0
    Some(r)
}

/// Minimal DNS response parser: returns (queried-name, ip) for each A/AAAA answer.
/// All answers are associated with the first question's QNAME (correct for host rules:
/// the user blocks the name they asked for, even when it CNAMEs to a CDN).
fn parse_dns_answers(buf: &[u8]) -> Vec<(String, IpAddr)> {
    let mut out = Vec::new();
    if buf.len() < 12 {
        return out;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if qdcount == 0 {
        return out;
    }
    // First question's name = the host we attribute answers to.
    let (qname, mut pos) = match read_dns_name(buf, 12) {
        Some(v) => v,
        None => return out,
    };
    pos += 4; // QTYPE + QCLASS
    for _ in 1..qdcount {
        pos = match skip_dns_name(buf, pos) {
            Some(p) => p + 4,
            None => return out,
        };
    }
    for _ in 0..ancount {
        pos = match skip_dns_name(buf, pos) {
            Some(p) => p,
            None => break,
        };
        if pos + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            break;
        }
        match (rtype, rdlen) {
            (1, 4) => out.push((
                qname.clone(),
                IpAddr::V4(Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3])),
            )),
            (28, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&buf[pos..pos + 16]);
                out.push((qname.clone(), IpAddr::V6(Ipv6Addr::from(o))));
            }
            _ => {}
        }
        pos += rdlen;
    }
    out
}

/// Best-effort SNI extractor for a TLS ClientHello. Returns the first `host_name` in the
/// server_name extension, or None if the buffer isn't a ClientHello / has no SNI / is truncated.
/// Every read is bounds-checked — this parses untrusted bytes straight off the wire (the N-1
/// lesson from the reviewed APK), so it must never panic or read out of bounds.
fn parse_tls_sni(buf: &[u8]) -> Option<String> {
    // TLS record header: content_type(1)=0x16 handshake, version(2), length(2).
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    // Handshake header at offset 5: msg_type(1)=0x01 ClientHello, length(3).
    let mut p = 5usize;
    if buf.get(p) != Some(&0x01) {
        return None;
    }
    p += 4; // msg_type(1) + length(3)
    p += 2 + 32; // client_version(2) + random(32)
    // session_id: 1-byte length + data.
    let sid = *buf.get(p)? as usize;
    p += 1 + sid;
    // cipher_suites: 2-byte length + data.
    let cs = u16::from_be_bytes([*buf.get(p)?, *buf.get(p + 1)?]) as usize;
    p += 2 + cs;
    // compression_methods: 1-byte length + data.
    let cm = *buf.get(p)? as usize;
    p += 1 + cm;
    // extensions: 2-byte length + data.
    let ext_total = u16::from_be_bytes([*buf.get(p)?, *buf.get(p + 1)?]) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(buf.len());
    while p + 4 <= ext_end {
        let etype = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let elen = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
        p += 4;
        if p + elen > ext_end {
            return None;
        }
        if etype == 0x0000 {
            // server_name extension: list_length(2), name_type(1)=0 host_name, name_length(2), name.
            let mut q = p + 2; // skip server_name_list length
            let ntype = *buf.get(q)?;
            let nlen = u16::from_be_bytes([*buf.get(q + 1)?, *buf.get(q + 2)?]) as usize;
            q += 3;
            if ntype == 0 && q + nlen <= buf.len() {
                return std::str::from_utf8(&buf[q..q + nlen]).ok().map(|s| s.to_string());
            }
            return None;
        }
        p += elen;
    }
    None
}

/// Collect the CNAME *target* names from a DNS response's answer section (for CNAME-uncloak).
/// Each CNAME's rdata is a domain name (possibly compressed) pointing at the next alias in the
/// chain; checking these against the blocklist catches trackers cloaked behind a first-party name.
fn dns_answer_cnames(buf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if buf.len() < 12 {
        return out;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = match skip_dns_name(buf, pos) {
            Some(p) => p + 4, // QTYPE + QCLASS
            None => return out,
        };
    }
    for _ in 0..ancount {
        pos = match skip_dns_name(buf, pos) {
            Some(p) => p,
            None => break,
        };
        if pos + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            break;
        }
        if rtype == 5 {
            // CNAME: rdata is a domain name (read_dns_name resolves any compression pointer).
            if let Some((name, _)) = read_dns_name(buf, pos) {
                out.push(name);
            }
        }
        pos += rdlen;
    }
    out
}

/// Reads a DNS name (handling compression pointers); returns (name, position after the name).
fn read_dns_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end_pos = start;
    let mut jumped = false;
    let mut guard = 0;
    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;
        guard += 1;
        if guard > 128 {
            return None;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return None;
            }
            if !jumped {
                end_pos = pos + 2;
            }
            jumped = true;
            pos = ((len & 0x3F) << 8) | buf[pos + 1] as usize;
            continue;
        }
        if len == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        }
        pos += 1;
        if pos + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[pos..pos + len]).to_string());
        pos += len;
    }
    Some((labels.join("."), end_pos))
}

fn skip_dns_name(buf: &[u8], start: usize) -> Option<usize> {
    read_dns_name(buf, start).map(|(_, p)| p)
}

/// Map the Kotlin DiagLevel (0 off / 1 info / 2 debug) to a log filter.
fn level_filter(level: i32) -> log::LevelFilter {
    match level {
        0 => log::LevelFilter::Off,
        1 => log::LevelFilter::Info,  // lifecycle only — per-connection lines are debug!, stay hidden
        _ => log::LevelFilter::Debug, // full: includes dns-sinkhole / SNI / per-connection hosts
    }
}

/// Set the EFFECTIVE log verbosity. The `log` macros short-circuit on `log::max_level()`, so
/// Off truly emits nothing (no connection metadata reaches logcat). Safe to call any time —
/// this is what makes the Settings → Diagnostics toggle take effect live.
fn set_log_level(level: i32) {
    log::set_max_level(level_filter(level));
}

/// Driven by the user's Settings → Diagnostics level (passed from Kotlin at nativeStart and
/// updated live via nativeSetLogLevel). android_logger is installed ONCE at its most verbose; the
/// real gate is `log::set_max_level`, so the level can change without restarting the process.
/// Default is OFF — a shipped build logs nothing and never leaks browsing destinations to logcat
/// unless a tech-savvy user opts in. FULL logs connection hostnames (that's its purpose).
/// Wraps android_logger and HARD-DROPS noisy netstack records. smoltcp emits a per-packet
/// `debug!("failed to transmit IP: device exhausted")` (target `smoltcp::iface::interface`) that under
/// sustained high throughput hits tens of thousands of lines/sec — enough to flood logcat and stall
/// the app at FULL diagnostics. The env_filter on android_logger's Config did NOT suppress it in
/// practice, so we filter by target here, in our own logger, which is bulletproof. Our own
/// firewall_core/qopsec records pass through; the live OFF/SIMPLE/FULL gate is still log::max_level().
struct FilteredLogger(android_logger::AndroidLogger);
impl log::Log for FilteredLogger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        if m.target().starts_with("smoltcp") || m.target().starts_with("netstack_smoltcp") {
            return m.level() <= log::Level::Warn && self.0.enabled(m);
        }
        self.0.enabled(m)
    }
    fn log(&self, r: &log::Record) {
        let t = r.target();
        if (t.starts_with("smoltcp") || t.starts_with("netstack_smoltcp")) && r.level() > log::Level::Warn {
            return;
        }
        self.0.log(r);
    }
    fn flush(&self) {
        self.0.flush();
    }
}

fn init_log(level: i32) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let inner = android_logger::AndroidLogger::new(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Debug)
                .with_tag("firewall_core"),
        );
        // Ignore the error if a logger was somehow already set; the gate below still applies.
        let _ = log::set_boxed_logger(Box::new(FilteredLogger(inner)));
    });
    set_log_level(level);
}
