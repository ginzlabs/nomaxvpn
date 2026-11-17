package com.example.nomax

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Ikev2VpnProfile
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnManager
import android.net.VpnProfileState
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import androidx.annotation.RequiresApi

/**
 * IKEv2 runs in Android's own client (VpnManager), not the Go core, like iOS's
 * NEVPNManager. [Tunnel]'s state follows the VPN network the system brings up.
 */
@RequiresApi(30)
object Ike {
    private const val TIMEOUT_MS = 30_000L
    private val main = Handler(Looper.getMainLooper())
    private var watch: ConnectivityManager.NetworkCallback? = null
    private var vpnNetwork: Network? = null
    private var startedAt = 0L

    /** Whether IKEv2, rather than [TunnelService], owns [Tunnel]'s state. */
    var active = false
        private set

    /** Installs the profile. Returns the system's consent screen if the user hasn't allowed it yet. */
    fun provision(ctx: Context, e: Enrollment): Intent? = vpn(ctx).provisionVpnProfile(profile(e))

    fun start(context: Context) {
        val ctx = context.applicationContext
        val e = Vault.load(ctx) ?: return fail(ctx, "Open NoMax and enter your PIN first.")
        if (provision(ctx, e) != null) return fail(ctx, "NoMax needs your permission to set up a VPN.")
        active = true
        Tunnel.error.value = null
        Tunnel.protocol.value = null
        Tunnel.state.value = Tunnel.State.Connecting
        watch(ctx)
        try {
            if (Build.VERSION.SDK_INT >= 33) vpn(ctx).startProvisionedVpnProfileSession()
            else @Suppress("DEPRECATION") vpn(ctx).startProvisionedVpnProfile()
        } catch (ex: Exception) {
            return fail(ctx, ex.message ?: "IKEv2 couldn't start.")
        }
        startedAt = SystemClock.elapsedRealtime()
        main.postDelayed({ checkConnecting(ctx) }, 1000)
    }

    fun stop(ctx: Context) {
        if (!active) return
        down(ctx)
        Tunnel.state.value = Tunnel.State.Off
    }

    /** Picks up a session that outlived the app, so the home screen shows it as connected. */
    fun sync(ctx: Context) {
        if (active || Tunnel.state.value != Tunnel.State.Off) return
        active = true
        watch(ctx)
    }

    /** Removes the profile from the system when this device leaves. */
    fun forget(ctx: Context) {
        stop(ctx)
        runCatching { vpn(ctx).deleteProvisionedVpnProfile() }
    }

    private fun profile(e: Enrollment): Ikev2VpnProfile {
        val ike = e.profile.getJSONObject("ikev2")
        val user = ike.getString("username")
        return Ikev2VpnProfile.Builder(ike.getString("server"), user)
            .setAuthUsernamePassword(user, ike.getString("password"), null)
            .setBypassable(false)
            .setMetered(false)
            .build()
    }

    private fun checkConnecting(ctx: Context) {
        if (!active || Tunnel.state.value != Tunnel.State.Connecting) return
        val failed = Build.VERSION.SDK_INT >= 33 &&
            vpn(ctx).provisionedVpnProfileState?.state == VpnProfileState.STATE_FAILED
        when {
            failed -> fail(ctx, "IKEv2 couldn't connect. Try another protocol.")
            SystemClock.elapsedRealtime() - startedAt > TIMEOUT_MS -> fail(ctx, "IKEv2 didn't connect in time. Try another protocol.")
            else -> main.postDelayed({ checkConnecting(ctx) }, 1000)
        }
    }

    private fun watch(context: Context) {
        if (watch != null) return
        val ctx = context.applicationContext
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(n: Network, caps: NetworkCapabilities) {
                if (caps.ownerUid != Process.myUid()) return
                main.post {
                    if (!active || vpnNetwork == n) return@post
                    vpnNetwork = n
                    Tunnel.since = System.currentTimeMillis()
                    Tunnel.protocol.value = Proto.IKEv2
                    Tunnel.state.value = Tunnel.State.On
                }
            }

            override fun onLost(n: Network) {
                main.post {
                    if (active && n == vpnNetwork) stop(ctx)
                }
            }
        }
        val req = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        ctx.getSystemService(ConnectivityManager::class.java).registerNetworkCallback(req, cb)
        watch = cb
    }

    private fun down(ctx: Context) {
        active = false
        vpnNetwork = null
        watch?.let { runCatching { ctx.getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) } }
        watch = null
        runCatching { vpn(ctx).stopProvisionedVpnProfile() }
        Tunnel.protocol.value = null
    }

    private fun fail(ctx: Context, msg: String) {
        down(ctx)
        Tunnel.error.value = msg
        Tunnel.state.value = Tunnel.State.Off
    }

    private fun vpn(ctx: Context) = ctx.getSystemService(VpnManager::class.java)
}
