package com.example.nomax

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.text.format.Formatter
import android.view.HapticFeedbackConstants
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.Crossfade
import androidx.compose.animation.SizeTransform
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.PI
import kotlin.math.roundToInt
import kotlin.math.sin
import kotlinx.coroutines.delay
import nomaxcore.Nomaxcore

/** Invite PINs and the App Review PIN both have 6 digits. */
private const val PIN_LENGTH = 6
private val CARD_WIDTH = 340.dp
private const val MARK_ASPECT = 460.8f / 522.24f

/** The colours Material's scheme doesn't cover: frosted cards and the connected green. */
@Immutable
private data class Glass(val fill: Color, val edge: Color, val green: Color)

private val LocalGlass = staticCompositionLocalOf { Glass(Color.Unspecified, Color.Unspecified, Color.Unspecified) }

/** One curve for every change, as in the iPhone app. */
private fun <T> smooth() = tween<T>(350, easing = FastOutSlowInEasing)

/** Always dark: black with light text and the system blue and green, like the iPhone app. */
@Composable
fun NoMaxTheme(content: @Composable () -> Unit) {
    val scheme = darkColorScheme(
        primary = Color(0xFF0A84FF), onPrimary = Color.White,
        background = Color.Black, onBackground = Color.White,
        surface = Color.Black, onSurface = Color.White,
        surfaceContainer = Color(0xFF1C1C1E), onSurfaceVariant = Color(0xFF8E8E93),
        error = Color(0xFFFF453A),
    )
    val glass = Glass(Color.White.copy(alpha = 0.08f), Color.White.copy(alpha = 0.12f), Color(0xFF30D158))
    CompositionLocalProvider(LocalGlass provides glass) {
        MaterialTheme(colorScheme = scheme, content = content)
    }
}

@Composable
private fun Modifier.glass(shape: Shape): Modifier {
    val g = LocalGlass.current
    return clip(shape).background(g.fill, shape).border(1.dp, g.edge, shape)
}

/** Replaces content in place when [key] changes: the old fades out where it stands while the new fades in. */
@Composable
private fun <T> Swap(key: T, modifier: Modifier = Modifier, alignment: Alignment = Alignment.Center, content: @Composable (T) -> Unit) {
    AnimatedContent(
        key,
        modifier.fillMaxWidth(),
        transitionSpec = {
            (fadeIn(smooth()) + scaleIn(smooth(), initialScale = 0.94f)) togetherWith
                (fadeOut(smooth()) + scaleOut(smooth(), targetScale = 1.04f)) using SizeTransform(clip = false)
        },
        contentAlignment = alignment,
        label = "swap",
    ) { Box(Modifier.fillMaxWidth(), contentAlignment = alignment) { content(it) } }
}

/** The brand mark, in silver. */
@Composable
private fun BrandMark(modifier: Modifier = Modifier) {
    Image(painterResource(R.drawable.mark_silver), contentDescription = null, modifier = modifier)
}

@Composable
fun App(model: Model, onConnect: () -> Unit, onTest: () -> Unit) {
    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Pushed(model.showCheck, "check", { CheckScreen(model) }) {
            Crossfade(model.enrollment == null, animationSpec = tween(500), label = "screen") { joining ->
                if (joining) {
                    EnrollScreen(model)
                } else {
                    Pushed(model.showLogs, "logs", { LogsScreen(model, onTest) }) { HomeScreen(model, onConnect) }
                }
            }
        }
    }
}

/** [top] slides in over [under] while [shown], like a pushed screen. */
@Composable
private fun Pushed(shown: Boolean, label: String, top: @Composable () -> Unit, under: @Composable () -> Unit) {
    AnimatedContent(
        shown,
        transitionSpec = {
            val dir = if (targetState) 1 else -1
            (fadeIn(smooth()) + slideInHorizontally(smooth()) { dir * it / 4 }) togetherWith
                (fadeOut(smooth()) + slideOutHorizontally(smooth()) { -dir * it / 4 })
        },
        label = label,
    ) { if (it) top() else under() }
}

@Composable
fun EnrollScreen(model: Model) {
    val ctx = LocalContext.current
    var pin by rememberSaveable { mutableStateOf("") }
    var focused by remember { mutableStateOf(false) }
    var shownError by remember { mutableStateOf("") }
    val focus = remember { FocusRequester() }
    val shake = remember { Animatable(0f) }
    val complete = pin.length == PIN_LENGTH
    val join = { if (complete && !model.busy) model.enroll(pin, deviceName(ctx)) }

    LaunchedEffect(model.pendingPin) {
        val p = model.pendingPin ?: return@LaunchedEffect
        model.pendingPin = null
        pin = p.filter(Char::isDigit).take(PIN_LENGTH)
        if (pin.length == PIN_LENGTH) model.enroll(pin, deviceName(ctx))
    }
    LaunchedEffect(model.error) {
        shownError = model.error ?: return@LaunchedEffect
        shake.snapTo(0f)
        shake.animateTo(1f, tween(400, easing = LinearEasing))
    }
    // After the launch screen has faded, so the keyboard doesn't rise over it.
    LaunchedEffect(Unit) {
        delay(500)
        focus.requestFocus()
    }
    val errorAlpha by animateFloatAsState(if (model.error == null) 0f else 1f, smooth(), label = "error")
    val busy by animateFloatAsState(if (model.busy) 1f else 0f, smooth(), label = "busy")

    // Only the system bars: the keyboard covers the bottom instead of pushing the content up.
    Box(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.systemBars), contentAlignment = Alignment.TopCenter) {
        Column(
            Modifier.widthIn(max = 420.dp).fillMaxWidth().padding(horizontal = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(96.dp))
            BrandMark(Modifier.height(72.dp).aspectRatio(MARK_ASPECT))
            Text("Enter PIN", Modifier.padding(top = 28.dp), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            Box(Modifier.padding(top = 24.dp), contentAlignment = Alignment.Center) {
                PinBoxes(
                    pin,
                    active = if (focused && !model.busy) pin.length else null,
                    Modifier.offset { IntOffset((8.dp.toPx() * sin(shake.value * PI * 4)).roundToInt(), 0) },
                )
                BasicTextField(
                    value = pin,
                    onValueChange = { v ->
                        pin = v.filter(Char::isDigit).take(PIN_LENGTH)
                        if (model.error != null) model.error = null
                    },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, imeAction = ImeAction.Go),
                    keyboardActions = KeyboardActions(onGo = { join() }),
                    singleLine = true,
                    textStyle = TextStyle(color = Color.Transparent),
                    cursorBrush = SolidColor(Color.Transparent),
                    modifier = Modifier.matchParentSize().alpha(0f).focusRequester(focus)
                        .onFocusChanged { focused = it.isFocused }
                        .semantics { contentDescription = "PIN" },
                )
            }
            Text(
                shownError,
                Modifier.padding(top = 14.dp).alpha(errorAlpha),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
                textAlign = TextAlign.Center,
                minLines = 2,
                maxLines = 2,
            )
            Button(
                onClick = join,
                enabled = complete && !model.busy,
                shape = CircleShape,
                modifier = Modifier.padding(top = 10.dp).fillMaxWidth().height(52.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text("Join", Modifier.alpha(1 - busy), fontWeight = FontWeight.Bold)
                    if (busy > 0f) {
                        CircularProgressIndicator(Modifier.size(20.dp).alpha(busy), color = LocalContentColor.current, strokeWidth = 2.dp)
                    }
                }
            }
            TextButton(onClick = model::startCheck, Modifier.padding(top = 10.dp)) {
                Text("Check connection", style = MaterialTheme.typography.bodySmall)
            }
            if (model.routes.size > 2) {
                var routeOpen by remember { mutableStateOf(false) }
                Box {
                    TextButton(onClick = { routeOpen = true }, enabled = !model.busy) {
                        Text("Route: ${model.route.title}", style = MaterialTheme.typography.bodySmall)
                    }
                    RouteMenu(model, routeOpen) { routeOpen = false }
                }
            }
        }
        VersionLabel(Modifier.align(Alignment.BottomCenter).padding(bottom = 12.dp))
    }
}

/** "Version 1.0.0 (46)", quietly at the foot of the main screens. */
@Composable
private fun VersionLabel(modifier: Modifier = Modifier) {
    Text(
        "Version ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})",
        modifier,
        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
        style = MaterialTheme.typography.labelSmall,
    )
}

/** Six boxes, three and three, with the next one to fill highlighted. */
@Composable
private fun PinBoxes(pin: String, active: Int?, modifier: Modifier = Modifier) {
    Row(modifier, horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        for (i in 0 until PIN_LENGTH) {
            if (i == PIN_LENGTH / 2) {
                Box(Modifier.size(12.dp, 3.dp).clip(CircleShape).background(MaterialTheme.colorScheme.onSurfaceVariant))
            }
            PinBox(pin.getOrNull(i), i == active)
        }
    }
}

@Composable
private fun PinBox(digit: Char?, active: Boolean) {
    val glass = LocalGlass.current
    val accent = MaterialTheme.colorScheme.primary
    val fill by animateColorAsState(if (active) accent.copy(alpha = 0.18f) else glass.fill, smooth(), label = "fill")
    val edge by animateColorAsState(if (active) accent.copy(alpha = 0.6f) else glass.edge, smooth(), label = "edge")
    val shape = RoundedCornerShape(14.dp)
    Box(Modifier.size(42.dp, 54.dp).clip(shape).background(fill).border(1.dp, edge, shape), contentAlignment = Alignment.Center) {
        AnimatedContent(
            digit,
            transitionSpec = {
                (fadeIn(smooth()) + scaleIn(smooth(), initialScale = 0.6f)) togetherWith
                    (fadeOut(smooth()) + scaleOut(smooth(), targetScale = 0.6f))
            },
            label = "digit",
        ) { d -> Text(d?.toString() ?: "", fontSize = 26.sp, fontWeight = FontWeight.SemiBold) }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(model: Model, onConnect: () -> Unit) {
    val ctx = LocalContext.current
    val state by Tunnel.state.collectAsState()
    val active by Tunnel.protocol.collectAsState()
    val tunnelError by Tunnel.error.collectAsState()
    var menu by remember { mutableStateOf(false) }
    var confirmLeave by remember { mutableStateOf(false) }
    var shownError by remember { mutableStateOf("") }
    val on = state != Tunnel.State.Off
    val connected = state == Tunnel.State.On
    val error = model.error ?: tunnelError
    val secondary = MaterialTheme.colorScheme.onSurfaceVariant
    val run by RunLog.run.collectAsState()
    val runDismissed by RunLog.dismissed.collectAsState()
    // Auto and Test show their run in place of the IP and settings cards, and a
    // run where nothing worked stays up until it's closed.
    val runShown = run?.let { r ->
        r.kind != RunState.Kind.Single && !runDismissed && (r.failed || (!r.finished && state == Tunnel.State.Connecting))
    } ?: false
    val lowerAlpha by animateFloatAsState(if (runShown) 0f else 1f, smooth(), label = "lower")
    var boxTop by remember { mutableFloatStateOf(0f) }
    var ipTop by remember { mutableFloatStateOf(0f) }

    LaunchedEffect(error) { if (error != null) shownError = error }
    LaunchedEffect(state) { model.tunnelChanged(state) }
    LaunchedEffect(connected) {
        while (connected) {
            model.pollStats()
            delay(1000)
        }
    }
    val now by produceState(System.currentTimeMillis(), connected) {
        while (connected) {
            value = System.currentTimeMillis()
            delay(1000)
        }
    }
    val connectedAlpha by animateFloatAsState(if (connected) 1f else 0f, smooth(), label = "connected")
    // Android's IKEv2 client doesn't report traffic.
    val statsAlpha by animateFloatAsState(if (connected && active != Proto.IKEv2) 1f else 0f, smooth(), label = "stats")
    val errorAlpha by animateFloatAsState(if (error == null) 0f else 1f, smooth(), label = "error")

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text("NoMax", fontWeight = FontWeight.SemiBold) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
                navigationIcon = {
                    Box {
                        IconButton(onClick = { menu = true }) {
                            Icon(painterResource(R.drawable.ic_more), contentDescription = "More")
                        }
                        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                            DropdownMenuItem(text = { Text(model.enrollment?.host.orEmpty()) }, onClick = {}, enabled = false)
                            DropdownMenuItem(text = { Text("Remove this device") }, onClick = {
                                menu = false
                                confirmLeave = true
                            })
                        }
                    }
                },
                actions = {
                    // With the tunnel up, the check would test the tunnel's path.
                    IconButton(onClick = model::startCheck, enabled = !on) {
                        Icon(painterResource(R.drawable.ic_check), contentDescription = "Check connection")
                    }
                    IconButton(onClick = { model.showLogs = true }) {
                        Icon(painterResource(R.drawable.ic_logs), contentDescription = "Logs")
                    }
                },
            )
        },
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize().onGloballyPositioned { boxTop = it.positionInRoot().y }) {
            Column(
                Modifier.fillMaxSize().padding(horizontal = 20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Spacer(Modifier.weight(1f))
                PowerButton(state) { if (on) model.disconnect() else onConnect() }

                Column(
                    Modifier.padding(top = 24.dp).fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Swap(statusLabel(state)) { Text(it, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold) }
                    Swap(active?.takeIf { connected }) { p -> Text(p?.let { "via ${it.title}" } ?: " ", color = secondary) }
                    Text(elapsed(now - Tunnel.since), Modifier.alpha(connectedAlpha), fontFamily = FontFamily.Monospace, color = secondary)
                    Row(Modifier.padding(top = 4.dp).alpha(statsAlpha), horizontalArrangement = Arrangement.spacedBy(24.dp)) {
                        Text("↓ ${bytes(ctx, model.rx)}", color = secondary)
                        Text("↑ ${bytes(ctx, model.tx)}", color = secondary)
                    }
                }

                Text(
                    shownError,
                    Modifier.padding(top = 8.dp).alpha(errorAlpha),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    textAlign = TextAlign.Center,
                    minLines = 2,
                    maxLines = 2,
                )

                // The unfolded panel, invisible, keeps its space, so folding the settings moves nothing.
                Box(
                    Modifier.padding(top = 8.dp).alpha(lowerAlpha).onGloballyPositioned { ipTop = it.positionInRoot().y },
                    contentAlignment = Alignment.TopCenter,
                ) {
                    HomePanel(model, settingsShown = true, enabled = false, Modifier.alpha(0f).clearAndSetSemantics {})
                    HomePanel(model, settingsShown = !on, enabled = !runShown)
                }

                Spacer(Modifier.weight(1f))
                VersionLabel(Modifier.padding(top = 4.dp, bottom = 8.dp))
            }
            // The card starts where the panel does and takes up to the space below it.
            AnimatedVisibility(
                visible = runShown,
                modifier = Modifier.align(Alignment.TopCenter).fillMaxHeight()
                    .padding(top = with(LocalDensity.current) { (ipTop - boxTop).coerceAtLeast(0f).toDp() }, start = 20.dp, end = 20.dp),
                enter = fadeIn(smooth()) + scaleIn(smooth(), initialScale = 0.96f),
                exit = fadeOut(smooth()) + scaleOut(smooth(), targetScale = 1.04f),
            ) {
                run?.let { r ->
                    RunCard(r, onShare = { share(ctx, RunLog.text(model.protocol)) }, onClose = { RunLog.dismissed.value = true })
                }
            }
        }
    }

    if (confirmLeave) {
        AlertDialog(
            onDismissRequest = { confirmLeave = false },
            title = { Text("Remove this device?") },
            text = { Text("You'll need a new PIN to join again.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmLeave = false
                    model.leave()
                }) { Text("Remove") }
            },
            dismissButton = { TextButton(onClick = { confirmLeave = false }) { Text("Cancel") } },
        )
    }
}

fun statusLabel(s: Tunnel.State) = when (s) {
    Tunnel.State.On -> "Connected"
    Tunnel.State.Connecting -> "Connecting…"
    Tunnel.State.Off -> "Not connected"
}

@Composable
private fun PowerButton(state: Tunnel.State, onClick: () -> Unit) {
    val glass = LocalGlass.current
    val view = LocalView.current
    val on = state != Tunnel.State.Off
    val fill by animateColorAsState(if (on) glass.green else glass.fill, smooth(), label = "power")
    val tint by animateColorAsState(if (on) Color.White else MaterialTheme.colorScheme.onBackground, smooth(), label = "icon")
    val edge by animateColorAsState(if (on) Color.Transparent else glass.edge, smooth(), label = "edge")
    val glow by animateDpAsState(if (on) 24.dp else 0.dp, smooth(), label = "glow")
    val pulse by rememberInfiniteTransition(label = "pulse")
        .animateFloat(1f, 0.45f, infiniteRepeatable(tween(700), RepeatMode.Reverse), label = "pulse")
    Box(
        Modifier.size(180.dp)
            .shadow(glow, CircleShape, ambientColor = glass.green, spotColor = glass.green)
            .clip(CircleShape)
            .background(fill)
            .border(1.dp, edge, CircleShape)
            .clickable {
                view.performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
                onClick()
            }
            .semantics {
                contentDescription = if (on) "Disconnect" else "Connect"
                role = Role.Button
            },
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            painterResource(R.drawable.ic_power),
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(72.dp).alpha(if (state == Tunnel.State.Connecting) pulse else 1f),
        )
    }
}

private sealed interface Shown {
    data class Found(val check: IpCheck) : Shown
    data object Unreachable : Shown
    data object Checking : Shown
    data object Idle : Shown
}

/**
 * What websites see, then protocol and always-on, on one card. The settings
 * fold away while the tunnel is on, since they change only while it's off.
 */
@Composable
private fun HomePanel(model: Model, settingsShown: Boolean, enabled: Boolean, modifier: Modifier = Modifier) {
    val ctx = LocalContext.current
    val primary = MaterialTheme.colorScheme.primary
    val secondary = MaterialTheme.colorScheme.onSurfaceVariant
    val edge = LocalGlass.current.edge
    var open by remember { mutableStateOf(false) }
    var routeOpen by remember { mutableStateOf(false) }
    Column(modifier.widthIn(max = CARD_WIDTH).fillMaxWidth().glass(RoundedCornerShape(22.dp))) {
        IpSection(model.ipResult, model.checkingIP, enabled) { model.checkIP() }
        AnimatedVisibility(
            visible = settingsShown,
            enter = expandVertically(smooth(), expandFrom = Alignment.Top) + fadeIn(smooth()),
            exit = shrinkVertically(smooth(), shrinkTowards = Alignment.Top) + fadeOut(smooth()),
        ) {
            Column {
                HorizontalDivider(Modifier.padding(horizontal = 18.dp), color = edge)
                Box {
                    Row(
                        Modifier.fillMaxWidth().clickable(enabled = enabled) { open = true }.padding(horizontal = 18.dp).height(52.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("Protocol", Modifier.weight(1f))
                        Text(model.protocol.title, color = primary)
                        Icon(painterResource(R.drawable.ic_unfold), contentDescription = null, tint = primary, modifier = Modifier.padding(start = 2.dp).size(18.dp))
                    }
                    DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                        model.protocols.forEach { p ->
                            DropdownMenuItem(text = { Text(p.title) }, onClick = {
                                open = false
                                model.choose(p)
                            })
                        }
                    }
                }
                if (model.routes.size > 2) {
                    HorizontalDivider(Modifier.padding(horizontal = 18.dp), color = edge)
                    Box {
                        Row(
                            Modifier.fillMaxWidth().clickable(enabled = enabled) { routeOpen = true }.padding(horizontal = 18.dp).height(52.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text("Route", Modifier.weight(1f))
                            Text(model.route.title, color = primary)
                            Icon(painterResource(R.drawable.ic_unfold), contentDescription = null, tint = primary, modifier = Modifier.padding(start = 2.dp).size(18.dp))
                        }
                        RouteMenu(model, routeOpen) { routeOpen = false }
                    }
                }
                HorizontalDivider(Modifier.padding(horizontal = 18.dp), color = edge)
                Row(
                    Modifier.fillMaxWidth().clickable(enabled = enabled) { ctx.startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }
                        .padding(horizontal = 18.dp).height(52.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("Always-on VPN", Modifier.weight(1f))
                    Text("Settings", color = secondary)
                    Icon(painterResource(R.drawable.ic_chevron_right), contentDescription = null, tint = secondary, modifier = Modifier.size(20.dp))
                }
            }
        }
    }
}

@Composable
private fun RouteMenu(model: Model, open: Boolean, close: () -> Unit) {
    DropdownMenu(expanded = open, onDismissRequest = close) {
        model.routes.forEach { r ->
            DropdownMenuItem(text = { Text(r.title) }, onClick = {
                close()
                model.chooseRoute(r)
            })
        }
    }
}

/** The IPv4 address and rough location websites see; tap to check again. The labels stay put and the values swap in place. */
@Composable
private fun IpSection(result: IpCheck.Result?, checking: Boolean, enabled: Boolean, onClick: () -> Unit) {
    val shown = when (result) {
        is IpCheck.Result.Found -> Shown.Found(result.check)
        IpCheck.Result.Unreachable -> Shown.Unreachable
        null -> if (checking) Shown.Checking else Shown.Idle
    }
    val dim by animateFloatAsState(if (checking && result != null) 0.55f else 1f, smooth(), label = "dim")
    val secondary = MaterialTheme.colorScheme.onSurfaceVariant
    val address = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.SemiBold)
    val place = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.SemiBold)
    Column(
        Modifier.fillMaxWidth().alpha(dim)
            .clickable(enabled = enabled && !checking, onClick = onClick)
            .padding(horizontal = 18.dp, vertical = 14.dp)
            .semantics(mergeDescendants = true) {},
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("IP", Modifier.width(30.dp), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, color = secondary, textAlign = TextAlign.Center)
            Spacer(Modifier.width(12.dp))
            Swap(shown, alignment = Alignment.CenterStart) { s ->
                when (s) {
                    is Shown.Found -> Text(s.check.ip, style = address.copy(fontFamily = FontFamily.Monospace), maxLines = 1)
                    Shown.Unreachable -> Text("Unavailable", style = address, color = secondary)
                    Shown.Checking -> Placeholder("000.000.000.000", address.copy(fontFamily = FontFamily.Monospace))
                    Shown.Idle -> Text("Tap to check", style = address, color = secondary)
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.width(30.dp), contentAlignment = Alignment.Center) {
                Swap(shown) { s ->
                    val flag = (s as? Shown.Found)?.check?.flag
                    if (flag != null) Text(flag, style = place)
                    else Icon(painterResource(R.drawable.ic_globe), contentDescription = null, tint = secondary, modifier = Modifier.size(20.dp))
                }
            }
            Spacer(Modifier.width(12.dp))
            Swap(shown, alignment = Alignment.CenterStart) { s ->
                when (s) {
                    is Shown.Found -> Text(s.check.place, style = place, maxLines = 1)
                    Shown.Unreachable -> Text("Tap to check again", style = place, color = secondary)
                    Shown.Checking -> Placeholder("United Kingdom · LHR", place)
                    Shown.Idle -> Text("Location", style = place, color = secondary)
                }
            }
        }
    }
}

/** A rounded block the size of [sample], while the real value loads. */
@Composable
private fun Placeholder(sample: String, style: TextStyle) {
    Text(
        sample,
        Modifier.background(MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.22f), RoundedCornerShape(6.dp)),
        style = style,
        color = Color.Transparent,
        maxLines = 1,
    )
}

private fun deviceName(ctx: Context) =
    Settings.Global.getString(ctx.contentResolver, Settings.Global.DEVICE_NAME) ?: Build.MODEL

private fun bytes(ctx: Context, n: Long) = Formatter.formatShortFileSize(ctx, n)

private fun elapsed(ms: Long): String {
    val s = (ms / 1000).coerceAtLeast(0)
    return "%d:%02d:%02d".format(s / 3600, s / 60 % 60, s % 60)
}

private fun share(ctx: Context, text: String, title: String = "Share log") {
    val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)
    ctx.startActivity(Intent.createChooser(send, title))
}

/** Auto or Test as it goes: each protocol's row turns from waiting to trying to worked or failed. */
@Composable
private fun RunCard(run: RunState, onShare: () -> Unit, onClose: () -> Unit) {
    val secondary = MaterialTheme.colorScheme.onSurfaceVariant
    val list = rememberLazyListState()
    LaunchedEffect(run.active) { run.active?.let { list.animateScrollToItem((it - 1).coerceAtLeast(0)) } }
    val progress = when {
        run.failed -> "None worked"
        run.finished -> "Done"
        else -> "${run.tried} of ${run.rows.size}"
    }
    Column(
        Modifier.padding(bottom = 12.dp).widthIn(max = CARD_WIDTH).fillMaxWidth().heightIn(max = 300.dp)
            .glass(RoundedCornerShape(22.dp)).padding(horizontal = 18.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                if (run.kind == RunState.Kind.Test) "Testing every protocol" else "Auto",
                Modifier.weight(1f),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Swap(progress, Modifier.width(110.dp), alignment = Alignment.CenterEnd) {
                Text(it, color = if (run.failed) MaterialTheme.colorScheme.error else secondary, style = MaterialTheme.typography.bodyMedium)
            }
        }
        Swap(run.headline, alignment = Alignment.CenterStart) {
            Text(it, color = secondary, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
        LazyColumn(Modifier.weight(1f, fill = false).fillMaxWidth(), state = list) {
            items(run.rows, key = { it.proto }) { RunRow(it) }
        }
        AnimatedVisibility(run.failed, enter = fadeIn(smooth()), exit = fadeOut(smooth())) {
            Row(Modifier.fillMaxWidth().padding(top = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = onShare, shape = CircleShape) {
                    Icon(painterResource(R.drawable.ic_share), contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Share log", fontWeight = FontWeight.SemiBold)
                }
                Spacer(Modifier.weight(1f))
                TextButton(onClick = onClose) { Text("Close") }
            }
        }
    }
}

@Composable
private fun RunRow(row: RunState.Row) {
    val secondary = MaterialTheme.colorScheme.onSurfaceVariant
    val alpha by animateFloatAsState(if (row.state == RunState.RowState.Pending) 0.45f else 1f, smooth(), label = "row")
    Row(Modifier.fillMaxWidth().alpha(alpha).padding(vertical = 5.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(22.dp), contentAlignment = Alignment.Center) {
            AnimatedContent(
                row.state,
                transitionSpec = {
                    (fadeIn(smooth()) + scaleIn(smooth(), initialScale = 0.6f)) togetherWith (fadeOut(smooth()) + scaleOut(smooth(), targetScale = 1.2f))
                },
                contentAlignment = Alignment.Center,
                label = "mark",
            ) { RowMark(it) }
        }
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(row.title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
            Swap(row.step, alignment = Alignment.CenterStart) {
                Text(it.ifEmpty { " " }, color = secondary, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun RowMark(s: RunState.RowState) {
    val secondary = MaterialTheme.colorScheme.onSurfaceVariant
    when (s) {
        RunState.RowState.Pending -> Box(Modifier.size(16.dp).border(1.5.dp, secondary, CircleShape))
        RunState.RowState.Trying -> CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
        RunState.RowState.Ok -> Dot(LocalGlass.current.green, "✓")
        RunState.RowState.Fail -> Dot(MaterialTheme.colorScheme.error, "✕")
    }
}

@Composable
private fun Dot(color: Color, mark: String) {
    Box(Modifier.size(18.dp).clip(CircleShape).background(color), contentAlignment = Alignment.Center) {
        Text(mark, color = Color.Black, fontSize = 11.sp, fontWeight = FontWeight.Bold)
    }
}

/** Everything the tunnel and the app did, newest first, to share when something doesn't work. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogsScreen(model: Model, onTest: () -> Unit) {
    val ctx = LocalContext.current
    val lines by RunLog.lines.collectAsState()
    val run by RunLog.run.collectAsState()
    val sections = remember(lines) { RunLog.sections(lines) }
    val testing = run?.let { it.kind == RunState.Kind.Test && !it.finished } ?: false
    val secondary = MaterialTheme.colorScheme.onSurfaceVariant
    val day = remember { SimpleDateFormat("d MMM, HH:mm", Locale.getDefault()) }
    var menu by remember { mutableStateOf(false) }
    var confirmClear by remember { mutableStateOf(false) }

    BackHandler { model.showLogs = false }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text("Logs", fontWeight = FontWeight.SemiBold) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
                navigationIcon = {
                    IconButton(onClick = { model.showLogs = false }) {
                        Icon(painterResource(R.drawable.ic_back), contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { share(ctx, RunLog.text(model.protocol)) }, enabled = lines.isNotEmpty()) {
                        Icon(painterResource(R.drawable.ic_share), contentDescription = "Share")
                    }
                    Box {
                        IconButton(onClick = { menu = true }) {
                            Icon(painterResource(R.drawable.ic_more), contentDescription = "More")
                        }
                        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                            DropdownMenuItem(text = { Text("Copy") }, enabled = lines.isNotEmpty(), onClick = {
                                menu = false
                                ctx.getSystemService(ClipboardManager::class.java)
                                    ?.setPrimaryClip(ClipData.newPlainText("NoMax log", RunLog.text(model.protocol)))
                            })
                            DropdownMenuItem(text = { Text("Clear") }, enabled = lines.isNotEmpty(), onClick = {
                                menu = false
                                confirmClear = true
                            })
                        }
                    }
                },
            )
        },
        bottomBar = {
            SendFoot(canSend = model.enrollment != null) {
                Button(
                    onClick = {
                        model.showLogs = false
                        onTest()
                    },
                    enabled = !testing,
                    shape = CircleShape,
                    contentPadding = HalfButtonPadding,
                    modifier = Modifier.weight(1f).height(52.dp),
                ) { Text("Test every protocol", fontWeight = FontWeight.SemiBold, maxLines = 1) }
            }
        },
    ) { pad ->
        if (sections.isEmpty()) {
            Box(Modifier.padding(pad).fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
                Text(
                    "Nothing yet. Every connection's steps show up here, so you can share them if a protocol doesn't work.",
                    color = secondary,
                    textAlign = TextAlign.Center,
                )
            }
        } else {
            LazyColumn(Modifier.fillMaxSize(), contentPadding = pad) {
                sections.forEach { s ->
                    item {
                        Text(
                            "${day.format(Date(s.start))} · ${s.title}",
                            Modifier.padding(start = 20.dp, end = 20.dp, top = 18.dp, bottom = 6.dp),
                            color = secondary,
                            style = MaterialTheme.typography.labelMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    items(s.lines) { LogLineRow(it) }
                }
            }
        }
    }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text("Clear the log?") },
            confirmButton = {
                TextButton(onClick = {
                    confirmClear = false
                    RunLog.clear(ctx)
                }) { Text("Clear") }
            },
            dismissButton = { TextButton(onClick = { confirmClear = false }) { Text("Cancel") } },
        )
    }
}

/**
 * The foot of Logs and the connection check: "Send to NoMax" beside the screen's
 * [main] button, and under a line saying how sending went. The outcome shows for
 * a minute, and while something still waits to go.
 */
private val HalfButtonPadding = PaddingValues(horizontal = 12.dp)

@Composable
private fun SendFoot(canSend: Boolean, main: @Composable RowScope.() -> Unit) {
    val ctx = LocalContext.current
    val status by Reports.status.collectAsState()
    val now by produceState(System.currentTimeMillis(), status) {
        while (true) {
            value = System.currentTimeMillis()
            delay(1000)
        }
    }
    val note = when {
        status.sending -> "Sending…"
        now - status.at < 60_000 -> status.message
        Reports.pending(ctx) -> "Waiting to send. It goes by itself once you're connected."
        else -> ""
    }
    val glass = LocalGlass.current
    Column(Modifier.fillMaxWidth().windowInsetsPadding(WindowInsets.navigationBars).padding(horizontal = 24.dp, vertical = 12.dp)) {
        if (note.isNotEmpty()) {
            Text(
                note,
                Modifier.fillMaxWidth().padding(bottom = 8.dp),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall,
                textAlign = TextAlign.Center,
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(
                onClick = { Reports.send(ctx) },
                enabled = canSend && !status.sending,
                shape = CircleShape,
                colors = ButtonDefaults.buttonColors(containerColor = glass.fill, contentColor = MaterialTheme.colorScheme.onSurface),
                border = BorderStroke(1.dp, glass.edge),
                contentPadding = HalfButtonPadding,
                modifier = Modifier.weight(1f).height(52.dp),
            ) { Text("Send to NoMax", fontWeight = FontWeight.SemiBold, maxLines = 1) }
            main()
        }
    }
}

/** How this network treats the server, step by step, with a verdict and the report to send. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CheckScreen(model: Model) {
    val ctx = LocalContext.current
    val report = model.check
    val done = report?.done == true
    val secondary = MaterialTheme.colorScheme.onSurfaceVariant

    BackHandler { model.closeCheck() }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text("Connection check", fontWeight = FontWeight.SemiBold) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
                navigationIcon = {
                    IconButton(onClick = model::closeCheck) {
                        Icon(painterResource(R.drawable.ic_back), contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { share(ctx, Nomaxcore.checkText(), "Share report") }, enabled = done) {
                        Icon(painterResource(R.drawable.ic_share), contentDescription = "Share")
                    }
                },
            )
        },
        bottomBar = {
            SendFoot(canSend = done && model.enrollment != null) {
                Button(
                    onClick = model::startCheck,
                    enabled = done,
                    shape = CircleShape,
                    contentPadding = HalfButtonPadding,
                    modifier = Modifier.weight(1f).height(52.dp),
                ) { Text("Check again", fontWeight = FontWeight.SemiBold, maxLines = 1) }
            }
        },
    ) { pad ->
        LazyColumn(Modifier.fillMaxSize(), contentPadding = pad) {
            item {
                Column(
                    Modifier.padding(horizontal = 16.dp, vertical = 8.dp).fillMaxWidth()
                        .glass(RoundedCornerShape(22.dp)).padding(horizontal = 18.dp, vertical = 14.dp),
                ) {
                    Swap(if (done) report?.verdict.orEmpty() else "", alignment = Alignment.CenterStart) { verdict ->
                        if (verdict.isNotEmpty()) {
                            Text(verdict, style = MaterialTheme.typography.bodyLarge)
                        } else {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                                Spacer(Modifier.width(12.dp))
                                Text("Checking how this network treats our server…", style = MaterialTheme.typography.bodyLarge)
                            }
                        }
                    }
                }
                Text(
                    "Sending shares this report and your log with us: your network's address and provider, and what reached our server. No keys or passwords.",
                    Modifier.padding(horizontal = 20.dp, vertical = 4.dp),
                    color = secondary,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            report?.groups?.forEach { (group, steps) ->
                item(key = group) {
                    Text(
                        group,
                        Modifier.padding(start = 20.dp, end = 20.dp, top = 18.dp, bottom = 6.dp),
                        color = secondary,
                        style = MaterialTheme.typography.labelMedium,
                    )
                }
                items(steps, key = { it.id }) { CheckRow(it) }
            }
        }
    }
}

@Composable
private fun CheckRow(s: CheckReport.Step) {
    val secondary = MaterialTheme.colorScheme.onSurfaceVariant
    Row(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(22.dp), contentAlignment = Alignment.Center) {
            AnimatedContent(s.state, transitionSpec = { fadeIn(smooth()) togetherWith fadeOut(smooth()) }, label = "mark") {
                when (it) {
                    "ok" -> Dot(LocalGlass.current.green, "✓")
                    "fail" -> Dot(MaterialTheme.colorScheme.error, "✕")
                    "info" -> Dot(secondary, "i")
                    "running" -> CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                    else -> Box(Modifier.size(16.dp).border(1.5.dp, secondary, CircleShape))
                }
            }
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(s.title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
            if (s.detail.isNotEmpty()) {
                SelectionContainer { Text(s.detail, color = secondary, style = MaterialTheme.typography.bodySmall) }
            }
        }
    }
}

@Composable
private fun LogLineRow(l: LogLine) {
    val secondary = MaterialTheme.colorScheme.onSurfaceVariant
    val time = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }
    val color = when (l.state) {
        "ok" -> LocalGlass.current.green
        "fail" -> MaterialTheme.colorScheme.error
        else -> secondary
    }
    val style = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp, lineHeight = 16.sp)
    Row(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 2.dp)) {
        Text(time.format(Date(l.t)), style = style, color = secondary)
        Text(RunLog.mark(l.state), Modifier.padding(horizontal = 8.dp), style = style, color = color)
        Text(
            buildAnnotatedString {
                if (l.proto.isNotEmpty()) {
                    withStyle(SpanStyle(fontWeight = FontWeight.Bold)) { append(RunLog.title(l.proto)) }
                    append(": ")
                }
                append(l.step)
            },
            style = style,
        )
    }
}
