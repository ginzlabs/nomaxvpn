package com.example.nomax

import android.app.Application
import android.graphics.Color
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.view.View
import android.view.ViewTreeObserver
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.annotation.RequiresApi
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import nomaxcore.Nomaxcore
import org.json.JSONObject

class MainActivity : ComponentActivity() {
    private val model: Model by viewModels()

    /** Whether the VPN permission being asked for is for Test rather than a connect. */
    private var consentForTest = false

    private val consent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode != RESULT_OK) model.error = "NoMax needs your permission to set up a VPN."
        else if (consentForTest) Tunnel.test(this)
        else Tunnel.start(this, model.protocol)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= 31 && savedInstanceState == null) fadeSplash()
        // The app is always dark, so the bars keep light icons in the system's light mode too.
        enableEdgeToEdge(SystemBarStyle.dark(Color.TRANSPARENT), SystemBarStyle.dark(Color.TRANSPARENT))
        handle(intent)
        setContent { NoMaxTheme { App(model, onConnect = ::connect, onTest = ::test) } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    override fun onResume() {
        super.onResume()
        model.refreshProfile()
        Reports.sendIfPending(this)
        if (Build.VERSION.SDK_INT >= 30 && model.protocol == Proto.IKEv2) Ike.sync(this)
    }

    /** Holds Android's launch screen (black, with the mark) a moment, then fades it out. */
    @RequiresApi(31)
    private fun fadeSplash() {
        val shown = SystemClock.uptimeMillis()
        val content = findViewById<View>(android.R.id.content)
        content.viewTreeObserver.addOnPreDrawListener(object : ViewTreeObserver.OnPreDrawListener {
            override fun onPreDraw(): Boolean {
                if (SystemClock.uptimeMillis() - shown < 400) return false
                content.viewTreeObserver.removeOnPreDrawListener(this)
                return true
            }
        })
        splashScreen.setOnExitAnimationListener { v ->
            v.animate().alpha(0f).setDuration(450).withEndAction { v.remove() }.start()
        }
    }

    private fun connect() {
        model.error = null
        val e = model.enrollment ?: return
        // The last run's card goes until the new run's first step arrives.
        RunLog.dismissed.value = true
        model.log("Connect with ${model.protocol.title}" + if (model.route == Route.Auto) "" else ", ${model.route.title}")
        val ask = if (Build.VERSION.SDK_INT >= 30 && model.protocol == Proto.IKEv2) {
            runCatching { Ike.provision(this, e) }.getOrElse {
                model.error = it.message ?: "Couldn't set up IKEv2."
                return
            }
        } else {
            VpnService.prepare(this)
        }
        consentForTest = false
        if (ask != null) consent.launch(ask) else Tunnel.start(this, model.protocol)
    }

    /** Tries every protocol, then connects with the quickest that worked. */
    private fun test() {
        model.error = null
        if (model.enrollment == null) return
        RunLog.dismissed.value = true
        model.log("Test every protocol")
        if (model.protocol == Proto.IKEv2) model.choose(Proto.Auto)
        val ask = VpnService.prepare(this)
        consentForTest = true
        if (ask != null) consent.launch(ask) else Tunnel.test(this)
    }

    /** nomax://join?pin=1234 from an invite QR code. */
    private fun handle(i: Intent?) {
        val u = i?.data ?: return
        if (u.scheme == "nomax" && u.host == "join" && model.enrollment == null) {
            model.pendingPin = u.getQueryParameter("pin")
        }
    }
}

class Model(app: Application) : AndroidViewModel(app) {
    private val ctx get() = getApplication<Application>()

    var enrollment by mutableStateOf(Vault.load(app))
        private set
    var protocol by mutableStateOf(Vault.protocol(app))
        private set
    var route by mutableStateOf(Vault.route(app))
        private set
    private var shownError by mutableStateOf<String?>(null)
    var error: String?
        get() = shownError
        set(v) {
            if (v != null && v != shownError) log("Error: $v")
            shownError = v
        }
    var busy by mutableStateOf(false)
        private set
    var showLogs by mutableStateOf(false)
    var showCheck by mutableStateOf(false)
        private set
    var check by mutableStateOf<CheckReport?>(null)
        private set
    private var checkJob: Job? = null
    private var lastState: Tunnel.State? = null
    /** The last IP check's answer in the log, so reopening the app doesn't repeat it. */
    private var loggedIp: String? = null

    init {
        RunLog.load(app)
    }

    fun log(step: String) = RunLog.app(ctx, step)

    /** Checks how this network treats the server; run it with the tunnel off. */
    fun startCheck() {
        showCheck = true
        check = null
        Nomaxcore.checkStart(enrollment?.host ?: BuildConfig.HOST, RunLog.appInfo())
        log("Connection check started")
        checkJob?.cancel()
        checkJob = viewModelScope.launch {
            while (true) {
                val r = withContext(Dispatchers.IO) { CheckReport.parse(Nomaxcore.checkState()) }
                if (r != null) check = r
                if (r?.done == true) {
                    log("Connection check: ${r.verdict}")
                    withContext(Dispatchers.IO) { Reports.keepCheck(ctx, Nomaxcore.checkText()) }
                    return@launch
                }
                delay(300)
            }
        }
    }

    fun closeCheck() {
        showCheck = false
        checkJob?.cancel()
        Nomaxcore.checkCancel()
    }

    fun disconnect() {
        if (RunLog.run.value?.finished == false) RunLog.dismissed.value = true
        log("Disconnect")
        Tunnel.stop(ctx)
    }
    var pendingPin by mutableStateOf<String?>(null)
    var rx by mutableLongStateOf(0)
        private set
    var tx by mutableLongStateOf(0)
        private set
    var ipResult by mutableStateOf<IpCheck.Result?>(null)
        private set
    var checkingIP by mutableStateOf(false)
        private set
    private var ipJob: Job? = null

    /** Protocols this server offers on the chosen route, for the picker. */
    val protocols get() = Proto.entries.filter { p -> enrollment?.offers(p, route) ?: true }

    /** The ways to the server this device has, for the picker. */
    val routes get() = Route.offered(enrollment)

    fun choose(p: Proto) {
        protocol = p
        Vault.setProtocol(ctx, p)
        if (Tunnel.state.value != Tunnel.State.Off) Tunnel.start(ctx, p)
    }

    /** A protocol the route doesn't have goes back to Auto. */
    fun chooseRoute(r: Route) {
        route = r
        Vault.setRoute(ctx, r)
        when {
            enrollment?.offers(protocol, r) == false -> choose(Proto.Auto)
            Tunnel.state.value != Tunnel.State.Off -> Tunnel.start(ctx, protocol)
        }
    }

    fun enroll(pin: String, deviceName: String) {
        if (busy) return
        busy = true
        error = null
        viewModelScope.launch {
            try {
                val key = Nomaxcore.generateKey()
                val pub = Nomaxcore.publicKey(key)
                val (token, profile) = withContext(Dispatchers.IO) {
                    Api(BuildConfig.HOST, route = route).enroll(pin, deviceName.ifBlank { "Android" }, pub)
                }
                val e = Enrollment(profile, token, key)
                Vault.save(ctx, e)
                enrollment = e
            } catch (ex: Exception) {
                error = ex.message ?: "Couldn't join."
            } finally {
                busy = false
            }
        }
    }

    fun refreshProfile() {
        val e = enrollment ?: return
        viewModelScope.launch {
            try {
                val p = withContext(Dispatchers.IO) { e.api(ctx).profile(e.deviceToken) }
                if (p.toString() != e.profile.toString()) {
                    val updated = e.copy(profile = p)
                    Vault.save(ctx, updated)
                    enrollment = updated
                    log("Profile updated")
                    if (!updated.offers(route)) chooseRoute(Route.Auto)
                    if (!updated.offers(protocol, route)) choose(Proto.Auto)
                }
            } catch (ex: ApiError) {
                if (ex.unauthorized) {
                    forget()
                    error = ex.message
                }
            } catch (ex: Exception) {
                // Offline or server unreachable: keep the cached profile.
                log("Couldn't refresh the profile: ${ex.message ?: ex}")
            }
        }
    }

    /** A new tunnel state means a new address: forget the old one and check once it has settled. */
    fun tunnelChanged(state: Tunnel.State) {
        if (lastState != null && lastState != state) log(statusLabel(state))
        lastState = state
        ipResult = null
        if (state == Tunnel.State.Connecting) {
            ipJob?.cancel()
            checkingIP = true
        } else {
            checkIP(delayMs = 1000)
        }
    }

    fun checkIP(delayMs: Long = 0) {
        ipJob?.cancel()
        checkingIP = true
        ipJob = viewModelScope.launch {
            delay(delayMs)
            val via = enrollment.takeIf { Tunnel.state.value == Tunnel.State.On }
            val r = withContext(Dispatchers.IO) { IpCheck.run(via) }
            ipResult = r
            checkingIP = false
            val seen = if (r is IpCheck.Result.Found) "Websites see ${r.check.ip}, ${r.check.place}" else "IP check got no answer"
            if (seen != loggedIp) log(seen)
            loggedIp = seen
        }
    }

    suspend fun pollStats() {
        if (Tunnel.protocol.value == Proto.IKEv2) return
        val s = withContext(Dispatchers.IO) { JSONObject(Nomaxcore.stats()) }
        rx = s.optLong("rx")
        tx = s.optLong("tx")
    }

    fun leave() {
        val e = enrollment ?: return
        viewModelScope.launch {
            withContext(Dispatchers.IO) { e.api(ctx).deleteDevice(e.deviceToken) }
            forget()
        }
    }

    private fun forget() {
        runCatching { Tunnel.stop(ctx) }
        if (Build.VERSION.SDK_INT >= 30) runCatching { Ike.forget(ctx) }
        Vault.clear(ctx)
        enrollment = null
    }
}
