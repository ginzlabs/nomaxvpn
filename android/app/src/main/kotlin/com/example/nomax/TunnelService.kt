package com.example.nomax

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.MutableStateFlow
import nomaxcore.Nomaxcore

/** Tunnel state, shared by the service and the UI (same process). */
object Tunnel {
    enum class State { Off, Connecting, On }

    val state = MutableStateFlow(State.Off)
    val protocol = MutableStateFlow<Proto?>(null)
    val error = MutableStateFlow<String?>(null)

    @Volatile
    var since = 0L

    /** Counts Disconnects, so a start that finishes after one doesn't turn the tunnel back on. */
    @Volatile
    var stops = 0

    /** The run the core began to replace a tunnel that stopped carrying traffic. */
    private var reconnect = 0L

    /** The core's mode that tries every protocol and keeps the quickest. */
    const val TEST = "test"

    /** Follows the core while it reconnects on its own, from [RunLog.poll]. */
    fun follow(ctx: Context, e: RunEvent, run: RunState?) {
        when {
            e.state == "start" && e.reconnect && state.value != State.Off -> {
                reconnect = e.run
                protocol.value = null
                state.value = State.Connecting
            }
            e.state == "done" && e.run == reconnect && e.proto.isNotEmpty() && state.value == State.Connecting -> {
                if (run?.id == e.run && run.kind == RunState.Kind.Auto) Vault.setLastGood(ctx, Nomaxcore.preferred())
                protocol.value = Proto.of(e.proto)
                since = System.currentTimeMillis()
                error.value = null
                state.value = State.On
                Reports.sendIfPending(ctx)
            }
            // A protocol picked by hand stays on when its traffic check fails.
            e.state == "done" && e.proto.isEmpty() && state.value == State.On && run?.id == e.run && run.kind == RunState.Kind.Single ->
                error.value = "${protocol.value?.title ?: "The tunnel"} is on, but nothing comes through it. Try Auto, or another protocol."
        }
    }

    fun start(ctx: Context, p: Proto) {
        if (Build.VERSION.SDK_INT >= 30) {
            if (p == Proto.IKEv2) return Ike.start(ctx)
            Ike.stop(ctx)
        }
        ctx.startService(Intent(ctx, TunnelService::class.java).putExtra(TunnelService.EXTRA_PROTOCOL, p.id))
    }

    fun test(ctx: Context) {
        if (Build.VERSION.SDK_INT >= 30) Ike.stop(ctx)
        ctx.startService(Intent(ctx, TunnelService::class.java).putExtra(TunnelService.EXTRA_PROTOCOL, TEST))
    }

    fun stop(ctx: Context) {
        error.value = null
        if (state.value == State.Off) return
        if (Build.VERSION.SDK_INT >= 30 && Ike.active) return Ike.stop(ctx)
        // Off at once: the service finishes taking the tunnel down on its own.
        stops++
        protocol.value = null
        state.value = State.Off
        ctx.startService(Intent(ctx, TunnelService::class.java).setAction(TunnelService.ACTION_STOP))
    }
}

/**
 * Runs the Go core on the VPN interface. The app itself is excluded from the
 * VPN, so the core's own sockets (WireGuard, Xray) reach the server directly.
 * Started by the app, or by the system for always-on VPN.
 */
class TunnelService : VpnService() {
    private val worker = Executors.newSingleThreadExecutor()
    /** Reads the core's run steps into [RunLog] while [worker] waits on the core. */
    private val poller = Executors.newSingleThreadScheduledExecutor()
    private var polling: ScheduledFuture<*>? = null
    /** Refreshes the saved profile while connected, as the app may not open for days. */
    private val refresher = Executors.newSingleThreadScheduledExecutor()
    private var refreshing: ScheduledFuture<*>? = null
    private var tun: ParcelFileDescriptor? = null
    private var network: ConnectivityManager.NetworkCallback? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // An Auto run holds the worker; cancelling it lets this command through.
        Nomaxcore.cancel()
        if (polling == null) polling = poller.scheduleWithFixedDelay({ RunLog.poll(this) }, 0, 300, TimeUnit.MILLISECONDS)
        if (intent?.action == ACTION_STOP) {
            worker.execute {
                down()
                stopSelf()
            }
            return START_NOT_STICKY
        }
        // Always-on starts this service even when IKEv2 is chosen; the Go core picks instead.
        val id = intent?.getStringExtra(EXTRA_PROTOCOL) ?: Vault.protocol(this).id
        val proto = if (id == Tunnel.TEST) id else Proto.of(id).takeUnless { it == Proto.IKEv2 }?.id ?: Proto.Auto.id
        worker.execute { up(proto) }
        if (refreshing == null) refreshing = refresher.scheduleWithFixedDelay({ refreshProfile() }, 6, 6, TimeUnit.HOURS)
        return START_STICKY
    }

    override fun onRevoke() {
        worker.execute {
            down()
            stopSelf()
        }
    }

    override fun onDestroy() {
        polling?.cancel(false)
        polling = null
        worker.execute {
            down()
            RunLog.poll(this)
        }
        worker.shutdown()
        poller.shutdown()
        refresher.shutdownNow()
        super.onDestroy()
    }

    /**
     * The next start reads the profile from [Vault], so a new address or relay is used
     * then. The app handles a removed device when it opens.
     */
    private fun refreshProfile() {
        runCatching {
            val e = Vault.load(this) ?: return
            val p = e.api(this).profile(e.deviceToken)
            if (p.toString() != e.profile.toString()) Vault.save(this, e.copy(profile = p))
        }
    }

    /** [proto] is a [Proto] id, or [Tunnel.TEST]. */
    private fun up(proto: String) {
        down()
        val stops = Tunnel.stops
        Tunnel.error.value = null
        Tunnel.state.value = Tunnel.State.Connecting
        val e = Vault.load(this)
        if (e == null) {
            fail("Open NoMax and enter your PIN first.")
            return
        }
        try {
            val endpoint = Nomaxcore.endpoint(e.profile.toString())
            if (endpoint.isEmpty()) return fail("Can't find ${e.host}.")
            val wg = e.profile.getJSONObject("wireguard")
            val b = Builder()
                .setSession("NoMax")
                .setMtu(wg.optInt("mtu").takeIf { it > 0 } ?: 1280)
                .addRoute("0.0.0.0", 0)
                .addDisallowedApplication(packageName)
                .setMetered(false)
                .setConfigureIntent(
                    PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
                )
            val addresses = wg.getJSONArray("address")
            for (i in 0 until addresses.length()) {
                val (ip, prefix) = addresses.getString(i).split("/")
                b.addAddress(ip, prefix.toInt())
                if (':' in ip) b.addRoute("::", 0)
            }
            val dns = wg.getJSONArray("dns")
            for (i in 0 until dns.length()) b.addDnsServer(dns.getString(i))
            val fd = b.establish() ?: throw IllegalStateException("NoMax isn't allowed to set up a VPN.")
            tun = fd
            // A Disconnect before the core's run began had nothing to cancel.
            if (Tunnel.stops != stops) return down()
            val used = try {
                Nomaxcore.start(e.profile.toString(), proto, Vault.route(this).id, Vault.lastGood(this), e.wgPrivateKey, fd.fd, endpoint)
            } finally {
                if (proto == Proto.Auto.id || proto == Tunnel.TEST) Vault.setLastGood(this, Nomaxcore.preferred())
            }
            if (Tunnel.stops != stops) return down()
            Tunnel.protocol.value = Proto.of(used)
            Tunnel.since = System.currentTimeMillis()
            Tunnel.state.value = Tunnel.State.On
            Reports.sendIfPending(this)
            watchNetwork()
        } catch (ex: Exception) {
            down()
            // Cancelled for a stop or another start, which is already queued.
            if (ex.message == "Stopped") return
            // Auto's error lists every protocol's reason; the run card shows them.
            fail(ex.message?.lineSequence()?.first() ?: ex.toString())
        }
    }

    private fun fail(msg: String) {
        RunLog.app(this, "Error: $msg")
        Tunnel.error.value = msg
        Tunnel.state.value = Tunnel.State.Off
        stopSelf()
    }

    private fun down() {
        network?.let { runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) } }
        network = null
        Nomaxcore.stop()
        tun?.close()
        tun = null
        Tunnel.protocol.value = null
        Tunnel.state.value = Tunnel.State.Off
    }

    /** Rebind WireGuard's sockets when the phone moves between Wi-Fi and mobile data. */
    private fun watchNetwork() {
        val cb = object : ConnectivityManager.NetworkCallback() {
            private var first = true
            override fun onAvailable(n: Network) {
                if (first) {
                    first = false
                    return
                }
                worker.execute { Nomaxcore.bumpSockets() }
            }
        }
        getSystemService(ConnectivityManager::class.java).registerDefaultNetworkCallback(cb)
        network = cb
    }

    companion object {
        const val ACTION_STOP = "com.example.nomax.STOP"
        const val EXTRA_PROTOCOL = "protocol"
    }
}
