package com.abid.speedmeter

import android.app.Activity
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.text.InputType
import android.util.Base64
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

class LoginFailed(msg: String) : Exception(msg)

/** Cumulative byte counters of one ONT interface. down = ONT -> your devices, up = devices -> ONT. */
class Counter(val name: String, val down: Long, val up: Long)

fun bps(v: Double): String = when {
    v >= 1e9 -> String.format("%.2f Gbps", v / 1e9)
    v >= 1e6 -> String.format("%.2f Mbps", v / 1e6)
    v >= 1e3 -> String.format("%.0f Kbps", v / 1e3)
    else -> String.format("%.0f bps", v)
}

fun fmtBytes(b: Long): String {
    var v = b.toDouble()
    val units = arrayOf("B", "KB", "MB", "GB", "TB")
    var i = 0
    while (v >= 1024.0 && i < 4) {
        v /= 1024.0
        i++
    }
    return if (i == 0) String.format("%.0f %s", v, units[i]) else String.format("%.2f %s", v, units[i])
}

/** The ONT byte counters are 32-bit and wrap around, so handle that. */
fun delta(cur: Long, prev: Long): Long {
    var d = cur - prev
    if (d < 0) d += 4294967296L
    if (d > 2147483648L) d = 0
    return d
}

// ---------------------------------------------------------------------------
// ONT client (Huawei HG8141 / HG8145 / HG8546 / HS8145C5 web interface)
// ---------------------------------------------------------------------------

class Ont(private val host: String, private val user: String, private val pass: String) {
    private var cookie: String? = null
    private var lastLogin = 0L
    private var everLoggedIn = false

    private class Resp(val code: Int, val setCookies: List<String>, val body: String)

    private fun request(method: String, path: String, body: String?, cookieHeader: String?): Resp {
        val c = URL("http://" + host + path).openConnection() as HttpURLConnection
        try {
            c.requestMethod = method
            c.connectTimeout = 4000
            c.readTimeout = 10000
            c.instanceFollowRedirects = false
            c.useCaches = false
            if (cookieHeader != null) c.setRequestProperty("Cookie", cookieHeader)
            if (body != null) {
                c.doOutput = true
                c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                c.outputStream.use { it.write(body.toByteArray()) }
            }
            val code = c.responseCode
            val stream = if (code >= 400) c.errorStream else c.inputStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            val sc = ArrayList<String>()
            for ((k, v) in c.headerFields) {
                if (k != null && k.equals("Set-Cookie", ignoreCase = true)) sc.addAll(v)
            }
            return Resp(code, sc, text)
        } finally {
            c.disconnect()
        }
    }

    /** Returns null on success, otherwise a human readable reason. */
    private fun login(): String? {
        lastLogin = System.currentTimeMillis()
        var token = ""
        try {
            // This firmware asks for the login token with a POST request
            val r = request("POST", "/asp/GetRandCount.asp", "", null)
            if (r.code == 200) token = r.body.filter { it.isLetterOrDigit() }
        } catch (e: Exception) {
            // some firmware does not need the token
        }
        val pw = Base64.encodeToString(pass.toByteArray(), Base64.NO_WRAP)
        val form = "UserName=" + URLEncoder.encode(user, "UTF-8") +
            "&PassWord=" + URLEncoder.encode(pw, "UTF-8") +
            "&Language=english&x.X_HW_Token=" + token
        val r = request("POST", "/login.cgi", form, "Cookie=body:Language:english:id=-1;path=/")
        for (h in r.setCookies) {
            if (h.contains("sid=")) {
                cookie = h.substringBefore(";")
                everLoggedIn = true
                return null
            }
        }
        cookie = null
        val tokenInfo = if (token.isEmpty()) " No login token was received from the ONT." else ""
        return "Login failed (HTTP " + r.code + ")." + tokenInfo + " Check the username and password."
    }

    private fun get(path: String): String {
        for (attempt in 1..2) {
            if (cookie == null) {
                if (everLoggedIn && System.currentTimeMillis() - lastLogin < 15000) {
                    throw Exception("Session lost, will retry login shortly")
                }
                val err = login()
                if (err != null) throw LoginFailed(err)
            }
            val r = request("GET", path, null, cookie)
            if (r.code == 401 || r.code == 403 || r.body.contains("txt_Username")) {
                cookie = null
                continue
            }
            return r.body
        }
        throw Exception("Session expired and re-login did not work")
    }

    fun read(): List<Counter> {
        val out = ArrayList<Counter>()

        // LAN ports: LANStats(domain, txPackets, txBytes, rxPackets, rxBytes)
        val eth = get("/html/amp/ethinfo/ethinfo.asp")
        val lanRe = Regex("""new LANStats\("([^"]*)","(\d+)","(\d+)","(\d+)","(\d+)"\)""")
        val portRe = Regex("""LANPort\.(\d+)""")
        for (m in lanRe.findAll(eth)) {
            val port = portRe.find(m.groupValues[1])?.groupValues?.get(1) ?: "?"
            out.add(Counter("LAN " + port, m.groupValues[3].toLong(), m.groupValues[5].toLong()))
        }

        // WiFi: stPacketInfo(domain, bytesSent, packetsSent, bytesReceived, packetsReceived)
        val wl = get("/html/amp/wlaninfo/wlaninfo.asp")
        val wlRe = Regex("""new stPacketInfo\("([^"]*)","(\d+)","(\d+)","(\d+)","(\d+)"\)""")
        val idxRe = Regex("""WLANConfiguration(?:\\x2e|\.)(\d+)""")
        for (m in wlRe.findAll(wl)) {
            val idx = idxRe.find(m.groupValues[1])?.groupValues?.get(1) ?: "?"
            val sent = m.groupValues[2].toLong()
            val recv = m.groupValues[4].toLong()
            if (sent == 0L && recv == 0L) continue
            out.add(Counter("WiFi " + idx, sent, recv))
        }
        return out
    }
}

// ---------------------------------------------------------------------------
// Graph
// ---------------------------------------------------------------------------

class GraphView(ctx: Context) : View(ctx) {
    private val down = ArrayList<Float>()
    private val up = ArrayList<Float>()

    private val pDown = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#34D399"); style = Paint.Style.STROKE; strokeWidth = 4f
    }
    private val pUp = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#60A5FA"); style = Paint.Style.STROKE; strokeWidth = 4f
    }
    private val pText = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#8A97B0"); textSize = 28f
    }

    fun add(d: Double, u: Double) {
        down.add(d.toFloat())
        up.add(u.toFloat())
        if (down.size > 300) {
            down.removeAt(0)
            up.removeAt(0)
        }
        invalidate()
    }

    private fun line(canvas: Canvas, data: ArrayList<Float>, paint: Paint, w: Float, h: Float, m: Float) {
        val path = Path()
        for (i in data.indices) {
            val x = i.toFloat() / (data.size - 1).toFloat() * w
            val y = h - data[i] / m * h
            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        canvas.drawPath(path, paint)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (down.size < 2) return
        val w = width.toFloat()
        val h = height.toFloat()
        var m = 100000f
        for (v in down) if (v > m) m = v
        for (v in up) if (v > m) m = v
        m *= 1.15f
        line(canvas, down, pDown, w, h, m)
        line(canvas, up, pUp, w, h, m)
        canvas.drawText(bps(m.toDouble()), 8f, 30f, pText)
    }
}

// ---------------------------------------------------------------------------
// Screen
// ---------------------------------------------------------------------------

class MainActivity : Activity() {
    private val cBg = Color.parseColor("#0B1220")
    private val cCard = Color.parseColor("#131C2E")
    private val cMut = Color.parseColor("#8A97B0")
    private val cGreen = Color.parseColor("#34D399")
    private val cBlue = Color.parseColor("#60A5FA")
    private val cRed = Color.parseColor("#F87171")
    private val cAmber = Color.parseColor("#FBBF24")

    private lateinit var root: FrameLayout
    private var onDashboard = false
    private var generation = 0

    private var tvDown: TextView? = null
    private var tvUp: TextView? = null
    private var tvStatus: TextView? = null
    private var tvSession: TextView? = null
    private var tvSources: TextView? = null
    private var graph: GraphView? = null

    private var totalDown = 0L
    private var totalUp = 0L
    private var peakDown = 0.0
    private var peakUp = 0.0

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    private fun prefs() = getSharedPreferences("ont", Context.MODE_PRIVATE)

    private fun configured(): Boolean = !prefs().getString("pass", "").isNullOrEmpty()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        window.statusBarColor = cBg
        window.navigationBarColor = cBg
        root = FrameLayout(this)
        root.setBackgroundColor(cBg)
        setContentView(root)
        if (configured()) showDashboard() else showSetup()
    }

    override fun onStart() {
        super.onStart()
        if (onDashboard && configured()) startPolling()
    }

    override fun onStop() {
        super.onStop()
        generation++
    }

    // ---- small view helpers ----

    private fun text(s: String, sp: Float, color: Int, bold: Boolean = false, mono: Boolean = false): TextView {
        val t = TextView(this)
        t.text = s
        t.textSize = sp
        t.setTextColor(color)
        if (mono) {
            t.typeface = if (bold) Typeface.create(Typeface.MONOSPACE, Typeface.BOLD) else Typeface.MONOSPACE
        } else if (bold) {
            t.typeface = Typeface.DEFAULT_BOLD
        }
        return t
    }

    private fun card(): LinearLayout {
        val l = LinearLayout(this)
        l.orientation = LinearLayout.VERTICAL
        l.setPadding(dp(16), dp(14), dp(16), dp(14))
        val bg = GradientDrawable()
        bg.setColor(cCard)
        bg.cornerRadius = dp(16).toFloat()
        l.background = bg
        val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        lp.setMargins(0, 0, 0, dp(12))
        l.layoutParams = lp
        return l
    }

    private fun page(): LinearLayout {
        root.removeAllViews()
        val scroll = ScrollView(this)
        val col = LinearLayout(this)
        col.orientation = LinearLayout.VERTICAL
        col.setPadding(dp(16), dp(28), dp(16), dp(24))
        scroll.addView(col)
        root.addView(scroll, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        return col
    }

    private fun field(hint: String, value: String, password: Boolean): EditText {
        val e = EditText(this)
        e.hint = hint
        e.setText(value)
        e.setTextColor(Color.WHITE)
        e.setHintTextColor(cMut)
        e.setSingleLine(true)
        e.inputType = if (password) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
        return e
    }

    // ---- setup screen ----

    private fun showSetup() {
        onDashboard = false
        generation++
        val col = page()
        col.addView(text("Speed Meter", 26f, Color.WHITE, true))
        val c = card()
        c.addView(text("Connect to your ONT", 16f, Color.WHITE, true))
        c.addView(text("Your phone must be connected to the ONT's WiFi.", 13f, cMut))
        c.addView(text("ONT address", 12f, cMut))
        val host = field("ONT address", prefs().getString("host", "192.168.100.1") ?: "192.168.100.1", false)
        c.addView(host)
        c.addView(text("Username", 12f, cMut))
        val user = field("Username", prefs().getString("user", "telecomadmin") ?: "telecomadmin", false)
        c.addView(user)
        c.addView(text("Password", 12f, cMut))
        val pass = field("Password", "", true)
        c.addView(pass)
        val msg = text("", 13f, cRed)
        c.addView(msg)
        val go = Button(this)
        go.text = "Start"
        go.setOnClickListener {
            val h = host.text.toString().trim()
            val u = user.text.toString().trim()
            val p = pass.text.toString()
            if (h.isEmpty() || u.isEmpty() || p.isEmpty()) {
                msg.text = "Please fill in all three boxes."
            } else {
                prefs().edit().putString("host", h).putString("user", u).putString("pass", p).apply()
                showDashboard()
                startPolling()
            }
        }
        c.addView(go)
        col.addView(c)
        col.addView(text("The password is only stored on this phone and only sent to your ONT.", 12f, cMut))
    }

    // ---- dashboard ----

    private fun showDashboard() {
        onDashboard = true
        totalDown = 0L; totalUp = 0L; peakDown = 0.0; peakUp = 0.0
        val col = page()

        val header = LinearLayout(this)
        header.orientation = LinearLayout.HORIZONTAL
        header.gravity = Gravity.CENTER_VERTICAL
        val title = text("Speed Meter", 22f, Color.WHITE, true)
        header.addView(title, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        val change = Button(this)
        change.text = "Change login"
        change.setOnClickListener { showSetup() }
        header.addView(change)
        col.addView(header)

        val c1 = card()
        c1.addView(text("TOTAL REALTIME SPEED  (WiFi + LAN)", 12f, cMut))
        val row = LinearLayout(this)
        row.orientation = LinearLayout.HORIZONTAL
        val left = LinearLayout(this)
        left.orientation = LinearLayout.VERTICAL
        left.addView(text("↓ DOWNLOAD", 12f, cMut))
        val d = text("-", 26f, cGreen, true, true)
        left.addView(d)
        val right = LinearLayout(this)
        right.orientation = LinearLayout.VERTICAL
        right.addView(text("↑ UPLOAD", 12f, cMut))
        val u = text("-", 26f, cBlue, true, true)
        right.addView(u)
        row.addView(left, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        row.addView(right, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        c1.addView(row)
        val st = text("Starting...", 13f, cAmber)
        c1.addView(st)
        col.addView(c1)

        val c2 = card()
        c2.addView(text("LAST 5 MINUTES", 12f, cMut))
        val g = GraphView(this)
        c2.addView(g, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(160)))
        col.addView(c2)

        val c3 = card()
        c3.addView(text("THIS SESSION", 12f, cMut))
        val ss = text("-", 14f, Color.WHITE, false, true)
        c3.addView(ss)
        col.addView(c3)

        val c4 = card()
        c4.addView(text("EACH PORT", 12f, cMut))
        val sr = text("-", 13f, Color.WHITE, false, true)
        c4.addView(sr)
        col.addView(c4)

        col.addView(text(
            "This adds up your WiFi and LAN-port counters. It also counts traffic between your own devices " +
                "(for example phone to PC), so it can read a little higher than your real internet speed.",
            12f, cMut
        ))

        tvDown = d; tvUp = u; tvStatus = st; tvSession = ss; tvSources = sr; graph = g
    }

    private fun setStatus(s: String, color: Int) {
        tvStatus?.text = s
        tvStatus?.setTextColor(color)
    }

    private fun onSample(down: Double, up: Double, dBytes: Long, uBytes: Long, rows: String) {
        totalDown += dBytes
        totalUp += uBytes
        if (down > peakDown) peakDown = down
        if (up > peakUp) peakUp = up
        tvDown?.text = bps(down)
        tvUp?.text = bps(up)
        graph?.add(down, up)
        tvSession?.text = "Downloaded  " + fmtBytes(totalDown) + "   peak " + bps(peakDown) + "\n" +
            "Uploaded    " + fmtBytes(totalUp) + "   peak " + bps(peakUp)
        tvSources?.text = rows
        setStatus("Live", cGreen)
    }

    // ---- polling ----

    private fun bindWifi() {
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            for (n in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(n) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                    cm.bindProcessToNetwork(n)
                    return
                }
            }
        } catch (e: Exception) {
            // not fatal
        }
    }

    private fun startPolling() {
        val gen = ++generation
        val p = prefs()
        val ont = Ont(
            p.getString("host", "192.168.100.1") ?: "192.168.100.1",
            p.getString("user", "telecomadmin") ?: "telecomadmin",
            p.getString("pass", "") ?: ""
        )
        setStatus("Connecting...", cAmber)
        Thread { poll(gen, ont) }.start()
    }

    private fun poll(gen: Int, ont: Ont) {
        bindWifi()
        var prev: Map<String, Counter>? = null
        var prevT = 0L
        while (gen == generation) {
            val t0 = System.nanoTime()
            try {
                val cur = ont.read().associateBy { it.name }
                val now = System.nanoTime()
                if (cur.isEmpty()) {
                    runOnUiThread {
                        if (gen == generation) setStatus("Logged in, but no counters were found on this ONT's pages.", cRed)
                    }
                } else {
                    val p = prev
                    if (p == null) {
                        runOnUiThread { if (gen == generation) setStatus("Connected. Measuring...", cAmber) }
                    } else {
                        val dt = (now - prevT) / 1e9
                        var dBytes = 0L
                        var uBytes = 0L
                        val rows = StringBuilder()
                        for ((name, c) in cur) {
                            val o = p[name] ?: continue
                            val d = delta(c.down, o.down)
                            val u = delta(c.up, o.up)
                            dBytes += d
                            uBytes += u
                            rows.append(String.format("%-6s ↓ %-12s ↑ %s\n", name, bps(d * 8 / dt), bps(u * 8 / dt)))
                        }
                        val down = dBytes * 8 / dt
                        val up = uBytes * 8 / dt
                        val text = rows.toString().trimEnd()
                        runOnUiThread { if (gen == generation) onSample(down, up, dBytes, uBytes, text) }
                    }
                    prev = cur
                    prevT = now
                }
            } catch (e: LoginFailed) {
                runOnUiThread {
                    if (gen == generation) setStatus((e.message ?: "Login failed") + " Tap Change login.", cRed)
                }
                return
            } catch (e: Exception) {
                prev = null
                val m = e.message ?: e.javaClass.simpleName
                runOnUiThread {
                    if (gen == generation) setStatus("Cannot read the ONT: " + m + ". Is the phone on the ONT's WiFi?", cRed)
                }
            }
            val spent = (System.nanoTime() - t0) / 1000000
            if (spent < 1000) {
                try {
                    Thread.sleep(1000 - spent)
                } catch (e: InterruptedException) {
                    return
                }
            }
        }
    }
}
