// The Nap browser on Android (DECISIONS §152).
//
// A full-screen dialog with its own WebView — not Tauri's, so a site here has
// no IPC, no wallet origin and no napvault. Nap's provider is injected at
// document start (androidx.webkit) for https origins (and localhost, for
// development); a page's request reaches the wallet as a `request` event with
// the origin the WebView reports for the sender (`WebMessageListener`), main
// frame only — never one the page claims. Approvals are a native dialog over
// the site; Approve arms after a pause.
package win.cavebro.napbrowser

import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.app.Dialog
import android.graphics.Color
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.KeyEvent
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import org.json.JSONObject

@InvokeArg
class OpenArgs {
    var url: String = ""
}

@InvokeArg
class RespondArgs {
    var id: Int = 0
    var json: String = "{}"
}

@InvokeArg
class ApproveArgs {
    var kicker: String = ""
    var title: String = ""
    var rows: List<List<String>> = emptyList()
    var note: String = ""
    var danger: Boolean = false
}

private const val PROVIDER = """
(() => {
  if (window.top !== window || window.zyn || typeof napBridge === 'undefined') return;
  if (!(location.protocol === 'https:' || (location.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(location.hostname)))) return;
  const bridge = napBridge;
  const pending = new Map();
  let seq = 0;
  class NapError extends Error { constructor(code, message) { super(message); this.code = code; } }
  bridge.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    const p = pending.get(m.id); if (!p) return; pending.delete(m.id);
    const payload = m.payload || {};
    if (payload.error) p.reject(new NapError(Number(payload.error.code) || -32603, String(payload.error.message || 'Nap refused')));
    else p.resolve(payload.result !== undefined ? payload.result : null);
  };
  const request = ({ method, params } = {}) => new Promise((resolve, reject) => {
    if (typeof method !== 'string') { reject(new NapError(-32602, 'method is required')); return; }
    const id = ++seq; pending.set(id, { resolve, reject });
    bridge.postMessage(JSON.stringify({ id, method, params: JSON.stringify(params || {}) }));
  });
  const provider = Object.freeze({ isNap: true, isNapApp: true, request });
  Object.defineProperty(window, 'zyn', { value: provider, writable: false, configurable: false });
  window.dispatchEvent(new Event('zyn#initialized'));
  const uuid = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
  const info = Object.freeze({ uuid, name: 'Nap Wallet', detail: 'Nap app', rdns: 'win.cavebro.nap.app', icon: '' });
  const announce = () => window.dispatchEvent(new CustomEvent('nap:announceProvider', { detail: Object.freeze({ info, provider }) }));
  window.addEventListener('nap:requestProvider', announce);
  announce();
})();
"""

private const val HOME = """
<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{margin:0;padding:28px 22px;background:#f8f2e4;color:#1f2428;font:17px system-ui,sans-serif}h1{font:800 30px system-ui;margin:8px 0 6px}p{color:#5a5f5c;margin:0 0 22px;line-height:1.45}
a{display:block;text-decoration:none;color:inherit;border:1px solid #1f24281f;background:#fffaf0;border-radius:14px;padding:16px 18px;margin:0 0 12px}a b{display:block;font-size:18px}a span{color:#6d716f;font-size:14px}</style>
<p style="font:600 12px monospace;letter-spacing:.14em;color:#9a6c00;margin:0">NAP BROWSER</p><h1>Sites that know Nap.</h1>
<p>A site you open here can ask Nap to connect or to approve something. Nothing moves until you say yes in Nap's own sheet.</p>
<a href="https://cave-market.pages.dev/"><b>Cave store</b><span>Private objects, found on Zcash</span></a>
<a href="https://cave-jade.pages.dev/"><b>Cave Jade</b><span>Coins on bonding curves, one price per epoch</span></a>
<a href="https://cavebro.win/mint"><b>Collection Z</b><span>Take a place in the cave</span></a>
<a href="https://scan.zyn-network.com/"><b>ZynScan</b><span>Every Zyn transaction, replayed</span></a>
"""

// The WebView's origin rules cannot say "any https origin" (only "*" or one
// host pattern), so the script and the listener both enforce it: https
// anywhere, http on this device only.
private val PROVIDER_ORIGINS = setOf("*")
private fun providerOrigin(u: Uri): Boolean {
    val s = u.scheme?.lowercase()
    return s == "https" || (s == "http" && (u.host == "localhost" || u.host == "127.0.0.1"))
}

@TauriPlugin
class NapBrowserPlugin(private val activity: Activity) : Plugin(activity) {
    private var dialog: Dialog? = null
    private var web: WebView? = null
    private var address: EditText? = null
    private val replies = HashMap<Int, JavaScriptReplyProxy>()
    private val main = Handler(Looper.getMainLooper())

    @Command
    fun open(invoke: Invoke) {
        val args = invoke.parseArgs(OpenArgs::class.java)
        activity.runOnUiThread {
            try {
                if (dialog == null) build()
                dialog?.show()
                val url = normalized(args.url)
                if (url != null) load(url) else home()
                invoke.resolve()
            } catch (e: Exception) {
                invoke.reject("The Nap browser could not open: ${e.message}")
            }
        }
    }

    @Command
    fun close(invoke: Invoke) {
        activity.runOnUiThread { dismissBrowser(); invoke.resolve() }
    }

    @Command
    fun respond(invoke: Invoke) {
        val args = invoke.parseArgs(RespondArgs::class.java)
        activity.runOnUiThread {
            val proxy = replies.remove(args.id)
            try {
                val msg = JSONObject().put("id", args.id).put("payload", JSONObject(args.json))
                proxy?.postMessage(msg.toString())
            } catch (_: Exception) {}
            invoke.resolve()
        }
    }

    @Command
    fun approve(invoke: Invoke) {
        val args = invoke.parseArgs(ApproveArgs::class.java)
        activity.runOnUiThread {
            val cream = Color.rgb(248, 242, 228)
            val body = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL; setPadding(56, 48, 56, 16) }
            fun label(text: String, size: Float, color: Int, bold: Boolean = false) = TextView(activity).apply {
                this.text = text; textSize = size; setTextColor(color); if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD); setPadding(0, 6, 0, 6)
            }
            body.addView(label(args.kicker.uppercase(), 12f, Color.rgb(232, 169, 22)))
            body.addView(label(args.title, 22f, cream, true))
            for (row in args.rows) if (row.size == 2) {
                body.addView(label(row[0], 13f, Color.argb(160, 248, 242, 228)))
                body.addView(label(row[1], 15f, cream))
            }
            if (args.note.isNotEmpty()) body.addView(label(args.note, 13f, Color.argb(190, 248, 242, 228)))
            val scroll = ScrollView(activity).apply { setBackgroundColor(Color.rgb(32, 37, 41)); addView(body) }
            var answered = false
            val answer = { ok: Boolean -> if (!answered) { answered = true; val r = JSObject(); r.put("approved", ok); invoke.resolve(r) } }
            val alert = AlertDialog.Builder(activity, android.R.style.Theme_DeviceDefault_Dialog_Alert)
                .setView(scroll)
                .setNegativeButton("Reject") { _, _ -> answer(false) }
                .setPositiveButton("Approve") { _, _ -> answer(true) }
                .setOnCancelListener { answer(false) }
                .create()
            alert.show()
            // Armed after a pause: a tap aimed at the page underneath cannot approve.
            val approveButton = alert.getButton(AlertDialog.BUTTON_POSITIVE)
            approveButton.isEnabled = false
            main.postDelayed({ approveButton.isEnabled = true }, 800)
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun build() {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER) || !WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
            throw IllegalStateException("this device's WebView is too old for the Nap browser; update Android System WebView")
        }
        val w = WebView(activity)
        w.settings.javaScriptEnabled = true
        w.settings.domStorageEnabled = true
        w.settings.setSupportMultipleWindows(false) // target=_blank opens here
        w.settings.javaScriptCanOpenWindowsAutomatically = false
        w.webChromeClient = WebChromeClient()
        w.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val s = request.url.scheme?.lowercase()
                return s != "https" && s != "http" // other schemes (intent:, file:, …) go nowhere
            }
            override fun onPageFinished(view: WebView, url: String?) {
                address?.setText(url?.let { Uri.parse(it).host } ?: "")
            }
        }
        WebViewCompat.addDocumentStartJavaScript(w, PROVIDER, PROVIDER_ORIGINS)
        WebViewCompat.addWebMessageListener(w, "napBridge", PROVIDER_ORIGINS) { _, message: WebMessageCompat, sourceOrigin: Uri, isMainFrame: Boolean, reply: JavaScriptReplyProxy ->
            if (!isMainFrame || !providerOrigin(sourceOrigin)) return@addWebMessageListener
            try {
                val m = JSONObject(message.data ?: return@addWebMessageListener)
                val id = m.getInt("id")
                replies[id] = reply
                val ev = JSObject()
                ev.put("id", id)
                ev.put("origin", origin(sourceOrigin))
                ev.put("method", m.getString("method"))
                ev.put("params", m.optString("params", "{}"))
                trigger("request", ev)
            } catch (_: Exception) {}
        }

        val ink = Color.rgb(31, 36, 40)
        val bar = LinearLayout(activity).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(12, 12, 12, 12) }
        fun button(text: String, onClick: () -> Unit) = Button(activity).apply {
            this.text = text; isAllCaps = false; setTextColor(ink); setBackgroundColor(Color.TRANSPARENT); minWidth = 0; minimumWidth = 0; setPadding(18, 0, 18, 0); setOnClickListener { onClick() }
        }
        val back = button("‹") { if (w.canGoBack()) w.goBack() else home() }.apply { textSize = 26f }
        val fwd = button("›") { if (w.canGoForward()) w.goForward() }.apply { textSize = 26f }
        val field = EditText(activity).apply {
            hint = "Site address"; setSingleLine(); textSize = 15f; setTextColor(ink)
            inputType = InputType.TYPE_TEXT_VARIATION_URI or InputType.TYPE_CLASS_TEXT
            imeOptions = EditorInfo.IME_ACTION_GO
            setOnEditorActionListener { v, action, event ->
                if (action == EditorInfo.IME_ACTION_GO || event?.keyCode == KeyEvent.KEYCODE_ENTER) { normalized(v.text.toString())?.let { load(it) }; true } else false
            }
        }
        address = field
        val done = button("Done") { dismissBrowser() }.apply { setTypeface(typeface, android.graphics.Typeface.BOLD) }
        bar.addView(back); bar.addView(fwd)
        bar.addView(field, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        bar.addView(done)
        val root = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.rgb(248, 242, 228)) }
        root.addView(bar, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        root.addView(w, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))

        val d = Dialog(activity, android.R.style.Theme_DeviceDefault_Light_NoActionBar)
        d.setContentView(root)
        d.window?.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        d.window?.clearFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND)
        d.setOnKeyListener { _, code, event ->
            if (code == KeyEvent.KEYCODE_BACK && event.action == KeyEvent.ACTION_UP) { if (w.canGoBack()) w.goBack() else dismissBrowser(); true } else false
        }
        d.setOnDismissListener { replies.clear() }
        dialog = d
        web = w
    }

    private fun dismissBrowser() {
        dialog?.dismiss()
        web?.destroy()
        dialog = null
        web = null
        address = null
        replies.clear()
    }

    private fun home() {
        web?.loadDataWithBaseURL(null, HOME, "text/html", "utf-8", null)
        address?.setText("")
    }

    private fun load(url: String) {
        web?.loadUrl(url)
        address?.setText(Uri.parse(url).host)
    }

    private fun normalized(raw: String): String? {
        val t = raw.trim()
        if (t.isEmpty()) return null
        val u = Uri.parse(if (t.contains("://")) t else "https://$t")
        val s = u.scheme?.lowercase()
        return if ((s == "https" || s == "http") && !u.host.isNullOrEmpty()) u.toString() else null
    }

    private fun origin(u: Uri): String {
        val scheme = u.scheme ?: return "null"
        val port = if (u.port == -1 || (scheme == "https" && u.port == 443) || (scheme == "http" && u.port == 80)) "" else ":${u.port}"
        return "$scheme://${u.host}$port"
    }
}
