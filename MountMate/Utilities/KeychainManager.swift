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

  // MARK: - Encrypted volume passwords (system keychain format)

  /// macOS saves passwords for encrypted volumes as generic-password items
  /// whose service and account are both the volume UUID — the "Encrypted
  /// Volume Password" items Finder's and Disk Utility's unlock dialogs
  /// create, and the ones diskmanagementd reads to auto-unlock a disk at
  /// attach time. Reading and writing that same entry (instead of a private
  /// MountMate-only copy under `serviceName`) keeps one shared password that
  /// works for both OS auto-unlock and MountMate.
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

  func saveEncryptedVolumePassword(
    _ password: String, volumeUUID: String, volumeName: String
  ) -> OSStatus {
    var attributes = encryptedVolumeQuery(volumeUUID: volumeUUID)
    attributes[kSecValueData as String] = password.data(using: .utf8)!
    // Match how the system stores these items so Keychain Access shows them
    // identically to passwords saved via Finder.
    attributes[kSecAttrLabel as String] = volumeName
    attributes[kSecAttrDescription as String] = "Encrypted Volume Password"

    SecItemDelete(encryptedVolumeQuery(volumeUUID: volumeUUID) as CFDictionary)
    return SecItemAdd(attributes as CFDictionary, nil)
  }

  func deleteEncryptedVolumePassword(volumeUUID: String) {
    SecItemDelete(encryptedVolumeQuery(volumeUUID: volumeUUID) as CFDictionary)
  }
}
