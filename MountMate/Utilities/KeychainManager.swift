//  Created by homielab.com

import Foundation
import Security

class KeychainManager {
  static let shared = KeychainManager()
  private let serviceName = "com.homielab.mountmate"

  private init() {}

  func save(password: String, for account: String) -> OSStatus {
    let data = password.data(using: .utf8)!
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: serviceName,
      kSecAttrAccount as String: account,
      kSecValueData as String: data,
    ]

    SecItemDelete(query as CFDictionary)
    return SecItemAdd(query as CFDictionary, nil)
  }

  func load(account: String) -> String? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: serviceName,
      kSecAttrAccount as String: account,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]

    var dataTypeRef: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)

    if status == errSecSuccess, let data = dataTypeRef as? Data {
      return String(data: data, encoding: .utf8)
    }
    return nil
  }

  func delete(account: String) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: serviceName,
      kSecAttrAccount as String: account,
    ]
    SecItemDelete(query as CFDictionary)
  }

  /// Whether MountMate holds any remembered passwords under its own service
  /// (encrypted volumes and network shares alike). Used to decide whether
  /// the DiskArbitration session needs to run.
  func hasAnyRememberedPasswords() -> Bool {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: serviceName,
    ]
    var result: AnyObject?
    return SecItemCopyMatching(query as CFDictionary, &result) != errSecItemNotFound
  }

  // MARK: - Encrypted volume passwords (system keychain format)

  /// macOS saves passwords for encrypted volumes as generic-password items
  /// whose service and account are both the volume UUID — the "Encrypted
  /// Volume Password" items Finder's and Disk Utility's unlock dialogs
  /// create, and the ones APFSUserAgent reads to auto-unlock a disk at
  /// attach time. Reading that entry lets MountMate reuse a password the
  /// user already saved with macOS.
  ///
  /// MountMate treats these items as strictly read-only. Writing them — even
  /// an in-place `SecItemUpdate` — invalidates the access list that lets
  /// APFSUserAgent read the item silently, making macOS prompt for the disk
  /// password on every plug-in (and APFSUserAgent's own updates of
  /// foreign-touched items fail with errSecMissingEntitlement on recent
  /// macOS). MountMate's own "remember password" therefore writes the app's
  /// private entry below, which is only a fallback for volumes the user
  /// never let macOS remember.
  private func encryptedVolumeQuery(volumeUUID: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: volumeUUID,
      kSecAttrAccount as String: volumeUUID,
    ]
  }

  func loadEncryptedVolumePassword(volumeUUID: String) -> String? {
    var query = encryptedVolumeQuery(volumeUUID: volumeUUID)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var dataTypeRef: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)

    guard status == errSecSuccess, let data = dataTypeRef as? Data else { return nil }
    return String(data: data, encoding: .utf8)
  }

  func deleteEncryptedVolumePassword(volumeUUID: String) {
    SecItemDelete(encryptedVolumeQuery(volumeUUID: volumeUUID) as CFDictionary)
  }
}
