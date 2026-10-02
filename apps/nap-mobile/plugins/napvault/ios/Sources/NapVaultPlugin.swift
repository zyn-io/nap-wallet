// Face ID / Touch ID unlock for Nap's kept wallet (DECISIONS §151).
//
// One secret — the kept wallet's password — in the Keychain, readable only
// after this device's currently enrolled biometrics say yes
// (`.biometryCurrentSet`): enrolling a new face or finger invalidates it, and
// it never leaves the device (`WhenPasscodeSetThisDeviceOnly`, no backup, no
// iCloud). Without it the wallet still opens with the password.
import LocalAuthentication
import Security
import SwiftRs
import Tauri
import UIKit
import WebKit

class StoreArgs: Decodable {
  let secret: String
}

class UnlockArgs: Decodable {
  let reason: String
}

private let service = "win.cavebro.nap.vault"
private let account = "kept-wallet-password"

private func baseQuery() -> [String: Any] {
  [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
}

class NapVaultPlugin: Plugin {
  @objc public func status(_ invoke: Invoke) {
    let ctx = LAContext()
    var err: NSError?
    let available = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
    var kind = "none"
    if available {
      switch ctx.biometryType {
      case .faceID: kind = "faceId"
      case .touchID: kind = "touchId"
      default: kind = "biometric"
      }
      if #available(iOS 17.0, *), ctx.biometryType == .opticID { kind = "opticId" }
    }
    // Whether the item exists, without asking for a face: a context that may
    // not interact answers "exists but needs auth" instead of prompting.
    let quiet = LAContext()
    quiet.interactionNotAllowed = true
    var q = baseQuery()
    q[kSecReturnAttributes as String] = true
    q[kSecUseAuthenticationContext as String] = quiet
    let st = SecItemCopyMatching(q as CFDictionary, nil)
    let stored = st == errSecSuccess || st == errSecInteractionNotAllowed
    invoke.resolve(["available": available, "kind": kind, "stored": stored])
  }

  @objc public func store(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(StoreArgs.self)
    SecItemDelete(baseQuery() as CFDictionary)
    var cfErr: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &cfErr) else {
      invoke.reject("This device cannot protect a secret with biometrics")
      return
    }
    var add = baseQuery()
    add[kSecValueData as String] = Data(args.secret.utf8)
    add[kSecAttrAccessControl as String] = access
    let st = SecItemAdd(add as CFDictionary, nil)
    if st == errSecSuccess { invoke.resolve() } else { invoke.reject("The Keychain refused (\(st))") }
  }

  @objc public func unlock(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(UnlockArgs.self)
    let ctx = LAContext()
    ctx.localizedFallbackTitle = ""  // no device-passcode fallback: the wallet password is the fallback
    // The face is checked here, explicitly, and the same approved context
    // then reads the Keychain item — whose own access control asks for the
    // current biometric set again on a device. Relying on the Keychain alone
    // is not enough everywhere: the simulator's Keychain does not enforce it.
    ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: args.reason) { ok, error in
      guard ok else {
        let code = (error as? LAError)?.code
        invoke.reject(code == .userCancel || code == .appCancel || code == .systemCancel || code == .userFallback ? "cancelled" : "Face ID did not recognise you")
        return
      }
      DispatchQueue.global(qos: .userInitiated).async {
        var q = baseQuery()
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        q[kSecUseAuthenticationContext as String] = ctx
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecSuccess, let data = out as? Data, let secret = String(data: data, encoding: .utf8) {
          invoke.resolve(["secret": secret])
        } else if st == errSecUserCanceled || st == errSecAuthFailed {
          invoke.reject("cancelled")
        } else if st == errSecItemNotFound {
          invoke.reject("not set up")
        } else {
          invoke.reject("Biometric unlock failed (\(st))")
        }
      }
    }
  }

  @objc public func forget(_ invoke: Invoke) {
    SecItemDelete(baseQuery() as CFDictionary)
    invoke.resolve()
  }
}

@_cdecl("init_plugin_napvault")
func initPlugin() -> Plugin {
  return NapVaultPlugin()
}
