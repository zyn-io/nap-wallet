// The Nap browser on iOS (DECISIONS §152).
//
// A full-screen controller with its own WKWebView — not Tauri's, so a site
// here has no IPC, no wallet origin and no napvault. Nap's provider is
// injected at document start into the main frame of https pages (and
// localhost, for development); a page's `request` reaches the wallet as a
// `request` event carrying the origin WebKit reports for the frame that sent
// it (`WKScriptMessage.frameInfo.securityOrigin`), never one the page claims.
// Approvals are a native sheet over the site; Approve arms after a pause so a
// double-tap aimed at the site cannot land on it.
import SwiftRs
import Tauri
import UIKit
import WebKit

class OpenArgs: Decodable {
  let url: String
}

class RespondArgs: Decodable {
  let id: Int
  let json: String
}

class ApproveArgs: Decodable {
  let kicker: String
  let title: String
  let rows: [[String]]
  let note: String
  let danger: Bool
}

/// What a site sees: the same interface as the extension and Nap in the
/// browser (apps/nap-connect), announced EIP-6963-style and as `window.zyn`.
let napProvider = """
(() => {
  if (window.top !== window || window.zyn) return;
  const send = (m) => window.webkit.messageHandlers.nap.postMessage(m);
  const pending = new Map();
  let seq = 0;
  class NapError extends Error { constructor(code, message) { super(message); this.code = code; } }
  Object.defineProperty(window, '__napReply', { value: (id, payload) => {
    const p = pending.get(id); if (!p) return; pending.delete(id);
    if (payload && payload.error) p.reject(new NapError(Number(payload.error.code) || -32603, String(payload.error.message || 'Nap refused')));
    else p.resolve(payload && payload.result !== undefined ? payload.result : null);
  }, writable: false, configurable: false });
  const request = ({ method, params } = {}) => new Promise((resolve, reject) => {
    if (typeof method !== 'string') { reject(new NapError(-32602, 'method is required')); return; }
    const id = ++seq; pending.set(id, { resolve, reject });
    send({ id, method, params: JSON.stringify(params || {}) });
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

/// The start page: where Nap's own sites are one tap away.
let napHome = """
<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{margin:0;padding:28px 22px;background:#f8f2e4;color:#1f2428;font:17px -apple-system,system-ui}h1{font:800 30px -apple-system;margin:8px 0 6px}p{color:#5a5f5c;margin:0 0 22px;line-height:1.45}
a{display:block;text-decoration:none;color:inherit;border:1px solid #1f24281f;background:#fffaf0;border-radius:14px;padding:16px 18px;margin:0 0 12px}a b{display:block;font-size:18px}a span{color:#6d716f;font-size:14px}</style>
<p style="font:600 12px ui-monospace,Menlo;letter-spacing:.14em;color:#9a6c00;margin:0">NAP BROWSER</p><h1>Sites that know Nap.</h1>
<p>A site you open here can ask Nap to connect or to approve something. Nothing moves until you say yes in Nap's own sheet.</p>
<a href="https://cave-market.pages.dev/"><b>Cave store</b><span>Private objects, found on Zcash</span></a>
<a href="https://cave-jade.pages.dev/"><b>Cave Jade</b><span>Coins on bonding curves, one price per epoch</span></a>
<a href="https://cavebro.win/mint"><b>Collection Z</b><span>Take a place in the cave</span></a>
<a href="https://scan.zyn-network.com/"><b>ZynScan</b><span>Every Zyn transaction, replayed</span></a>
"""

func isProviderOrigin(_ o: WKSecurityOrigin) -> Bool {
  o.protocol == "https" || (o.protocol == "http" && (o.host == "localhost" || o.host == "127.0.0.1"))
}

func originString(_ o: WKSecurityOrigin) -> String {
  let port = (o.port == 0 || (o.protocol == "https" && o.port == 443) || (o.protocol == "http" && o.port == 80)) ? "" : ":\(o.port)"
  return "\(o.protocol)://\(o.host)\(port)"
}

class BrowserController: UIViewController, WKScriptMessageHandler, WKNavigationDelegate, WKUIDelegate, UITextFieldDelegate {
  weak var plugin: NapBrowserPlugin?
  var web: WKWebView!
  let address = UITextField()
  let back = UIButton(type: .system)
  let forward = UIButton(type: .system)
  var pendingURL: URL?

  override func viewDidLoad() {
    super.viewDidLoad()
    let ground = UIColor(red: 0.973, green: 0.949, blue: 0.894, alpha: 1)
    view.backgroundColor = ground

    let config = WKWebViewConfiguration()
    let controller = WKUserContentController()
    controller.addUserScript(WKUserScript(source: napProvider, injectionTime: .atDocumentStart, forMainFrameOnly: true))
    controller.add(WeakHandler(self), name: "nap")
    config.userContentController = controller
    config.websiteDataStore = .default()
    web = WKWebView(frame: .zero, configuration: config)
    web.navigationDelegate = self
    web.uiDelegate = self
    web.allowsBackForwardNavigationGestures = true

    let close = UIButton(type: .system)
    close.setTitle("Done", for: .normal)
    close.titleLabel?.font = .boldSystemFont(ofSize: 17)
    close.tintColor = UIColor(red: 0.12, green: 0.14, blue: 0.16, alpha: 1)
    close.addTarget(self, action: #selector(done), for: .touchUpInside)
    address.borderStyle = .none
    address.backgroundColor = UIColor.white.withAlphaComponent(0.7)
    address.layer.cornerRadius = 10
    address.font = .systemFont(ofSize: 15)
    address.keyboardType = .URL
    address.autocapitalizationType = .none
    address.autocorrectionType = .no
    address.returnKeyType = .go
    address.clearButtonMode = .whileEditing
    address.placeholder = "Site address"
    address.delegate = self
    address.leftView = UIView(frame: CGRect(x: 0, y: 0, width: 10, height: 10))
    address.leftViewMode = .always
    back.setTitle("‹", for: .normal)
    forward.setTitle("›", for: .normal)
    for b in [back, forward] { b.titleLabel?.font = .systemFont(ofSize: 30); b.tintColor = close.tintColor }
    back.addTarget(self, action: #selector(goBack), for: .touchUpInside)
    forward.addTarget(self, action: #selector(goForward), for: .touchUpInside)

    let bar = UIStackView(arrangedSubviews: [back, forward, address, close])
    bar.spacing = 8
    bar.alignment = .center
    for v in [bar, web!] as [UIView] { v.translatesAutoresizingMaskIntoConstraints = false; view.addSubview(v) }
    NSLayoutConstraint.activate([
      bar.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 6),
      bar.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 10),
      bar.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),
      address.heightAnchor.constraint(equalToConstant: 38),
      back.widthAnchor.constraint(equalToConstant: 28),
      forward.widthAnchor.constraint(equalToConstant: 28),
      web.topAnchor.constraint(equalTo: bar.bottomAnchor, constant: 6),
      web.leadingAnchor.constraint(equalTo: view.leadingAnchor),
      web.trailingAnchor.constraint(equalTo: view.trailingAnchor),
      web.bottomAnchor.constraint(equalTo: view.bottomAnchor),
    ])
    if let url = pendingURL { load(url) } else { home() }
  }

  func home() {
    web.loadHTMLString(napHome, baseURL: nil)
    address.text = ""
    refreshButtons()
  }

  func load(_ url: URL) {
    web.load(URLRequest(url: url))
    address.text = url.host
  }

  func open(_ raw: String) {
    guard let url = normalized(raw) else { if isViewLoaded { home() }; return }
    if isViewLoaded { load(url) } else { pendingURL = url }
  }

  func normalized(_ raw: String) -> URL? {
    let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    if t.isEmpty { return nil }
    let withScheme = t.contains("://") ? t : "https://\(t)"
    guard let url = URL(string: withScheme), let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http", url.host != nil else { return nil }
    return url
  }

  @objc func done() {
    plugin?.browser = nil
    dismiss(animated: true)
  }
  @objc func goBack() { if web.canGoBack { web.goBack() } else { home() } }
  @objc func goForward() { if web.canGoForward { web.goForward() } }
  func refreshButtons() { back.isEnabled = true; forward.isEnabled = web?.canGoForward ?? false }

  func textFieldShouldReturn(_ field: UITextField) -> Bool {
    field.resignFirstResponder()
    open(field.text ?? "")
    return true
  }

  func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
    if let host = webView.url?.host { address.text = host }
    refreshButtons()
  }

  // A site's new-window link opens here, in the same view.
  func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration, for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
    if navigationAction.targetFrame == nil, let url = navigationAction.request.url { webView.load(URLRequest(url: url)) }
    return nil
  }

  func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
    // Only the main frame of a provider origin speaks for a site.
    guard message.frameInfo.isMainFrame, isProviderOrigin(message.frameInfo.securityOrigin),
      let body = message.body as? [String: Any], let id = body["id"] as? Int, let method = body["method"] as? String
    else { return }
    let params = body["params"] as? String ?? "{}"
    plugin?.forward(id: id, origin: originString(message.frameInfo.securityOrigin), method: method, params: params)
  }

  func reply(id: Int, json: String) {
    let safe = json.replacingOccurrences(of: "\u{2028}", with: "\\u2028").replacingOccurrences(of: "\u{2029}", with: "\\u2029")
    web?.evaluateJavaScript("window.__napReply && window.__napReply(\(id), \(safe))", completionHandler: nil)
  }
}

/// WKUserContentController keeps its handlers strongly; this breaks the cycle.
class WeakHandler: NSObject, WKScriptMessageHandler {
  weak var target: WKScriptMessageHandler?
  init(_ t: WKScriptMessageHandler) { target = t }
  func userContentController(_ c: WKUserContentController, didReceive m: WKScriptMessage) { target?.userContentController(c, didReceive: m) }
}

class ApprovalController: UIViewController {
  var args: ApproveArgs!
  var answer: ((Bool) -> Void)?
  let approve = UIButton(type: .system)

  override func viewDidLoad() {
    super.viewDidLoad()
    view.backgroundColor = UIColor(red: 0.125, green: 0.145, blue: 0.16, alpha: 1)
    let cream = UIColor(red: 0.973, green: 0.949, blue: 0.894, alpha: 1)
    let amber = UIColor(red: 0.91, green: 0.663, blue: 0.086, alpha: 1)
    let kicker = UILabel(); kicker.text = args.kicker.uppercased(); kicker.font = .monospacedSystemFont(ofSize: 12, weight: .medium); kicker.textColor = amber; kicker.numberOfLines = 2
    let title = UILabel(); title.text = args.title; title.font = .systemFont(ofSize: 26, weight: .heavy); title.textColor = cream; title.numberOfLines = 0
    let stack = UIStackView(arrangedSubviews: [kicker, title])
    stack.axis = .vertical; stack.spacing = 10
    for row in args.rows where row.count == 2 {
      let k = UILabel(); k.text = row[0]; k.textColor = cream.withAlphaComponent(0.6); k.font = .systemFont(ofSize: 14); k.numberOfLines = 0
      let v = UILabel(); v.text = row[1]; v.textColor = cream; v.font = .systemFont(ofSize: 15, weight: .medium); v.numberOfLines = 0
      let r = UIStackView(arrangedSubviews: [k, v]); r.axis = .vertical; r.spacing = 2
      stack.addArrangedSubview(r)
    }
    if !args.note.isEmpty { let n = UILabel(); n.text = args.note; n.textColor = cream.withAlphaComponent(0.7); n.font = .systemFont(ofSize: 14); n.numberOfLines = 0; stack.addArrangedSubview(n) }
    let reject = UIButton(type: .system)
    reject.setTitle("Reject", for: .normal); reject.tintColor = cream
    reject.layer.borderColor = cream.withAlphaComponent(0.4).cgColor; reject.layer.borderWidth = 1; reject.layer.cornerRadius = 10
    reject.addTarget(self, action: #selector(no), for: .touchUpInside)
    approve.setTitle("Approve", for: .normal); approve.setTitleColor(UIColor(red: 0.12, green: 0.14, blue: 0.16, alpha: 1), for: .normal)
    approve.backgroundColor = args.danger ? UIColor(red: 0.79, green: 0.33, blue: 0.27, alpha: 1) : amber
    approve.titleLabel?.font = .boldSystemFont(ofSize: 17); approve.layer.cornerRadius = 10
    approve.addTarget(self, action: #selector(yes), for: .touchUpInside)
    approve.isEnabled = false; approve.alpha = 0.45
    let buttons = UIStackView(arrangedSubviews: [reject, approve]); buttons.spacing = 12; buttons.distribution = .fillEqually
    buttons.heightAnchor.constraint(equalToConstant: 50).isActive = true
    stack.addArrangedSubview(buttons); stack.setCustomSpacing(22, after: stack.arrangedSubviews[stack.arrangedSubviews.count - 2])
    let scroll = UIScrollView(); scroll.translatesAutoresizingMaskIntoConstraints = false; stack.translatesAutoresizingMaskIntoConstraints = false
    view.addSubview(scroll); scroll.addSubview(stack)
    NSLayoutConstraint.activate([
      scroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 24),
      scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 22),
      scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -22),
      scroll.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -12),
      stack.topAnchor.constraint(equalTo: scroll.topAnchor), stack.bottomAnchor.constraint(equalTo: scroll.bottomAnchor),
      stack.leadingAnchor.constraint(equalTo: scroll.leadingAnchor), stack.trailingAnchor.constraint(equalTo: scroll.trailingAnchor),
      stack.widthAnchor.constraint(equalTo: scroll.widthAnchor),
    ])
    // Armed after a pause: a tap aimed at the page underneath cannot approve.
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) { [weak self] in self?.approve.isEnabled = true; self?.approve.alpha = 1 }
  }

  @objc func yes() { finish(true) }
  @objc func no() { finish(false) }
  func finish(_ ok: Bool) {
    let a = answer; answer = nil
    dismiss(animated: true) { a?(ok) }
  }
  override func viewDidDisappear(_ animated: Bool) {
    super.viewDidDisappear(animated)
    if let a = answer { answer = nil; a(false) }  // swiped away: a rejection
  }
}

class NapBrowserPlugin: Plugin {
  var browser: BrowserController?

  func forward(id: Int, origin: String, method: String, params: String) {
    trigger("request", data: ["id": id, "origin": origin, "method": method, "params": params])
  }

  @objc public func open(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(OpenArgs.self)
    DispatchQueue.main.async {
      if let b = self.browser { b.open(args.url); invoke.resolve(); return }
      guard let root = self.manager.viewController else { invoke.reject("no window to open the browser over"); return }
      let b = BrowserController()
      b.plugin = self
      b.modalPresentationStyle = .fullScreen
      b.open(args.url)
      self.browser = b
      root.present(b, animated: true) { invoke.resolve() }
    }
  }

  @objc public func close(_ invoke: Invoke) {
    DispatchQueue.main.async {
      self.browser?.dismiss(animated: true)
      self.browser = nil
      invoke.resolve()
    }
  }

  @objc public func respond(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(RespondArgs.self)
    DispatchQueue.main.async {
      self.browser?.reply(id: args.id, json: args.json)
      invoke.resolve()
    }
  }

  @objc public func approve(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(ApproveArgs.self)
    DispatchQueue.main.async {
      guard let over = self.browser ?? self.manager.viewController else { invoke.resolve(["approved": false]); return }
      let sheet = ApprovalController()
      sheet.args = args
      sheet.answer = { ok in invoke.resolve(["approved": ok]) }
      sheet.modalPresentationStyle = .pageSheet
      if let s = sheet.sheetPresentationController { s.detents = [.large()]; s.prefersGrabberVisible = false }
      sheet.isModalInPresentation = true
      over.present(sheet, animated: true)
    }
  }
}

@_cdecl("init_plugin_napbrowser")
func initPlugin() -> Plugin {
  return NapBrowserPlugin()
}
