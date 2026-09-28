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

  /// Where a remembered encrypted-volume password was stored.
  enum RememberedPasswordSave {
    /// The system "Encrypted Volume Password" keychain entry was updated in
    /// place.
    case systemEntryUpdated
    /// MountMate's own keychain entry was created, because no system entry
    /// existed.
    case privateEntrySaved
  }

  /// macOS saves passwords for encrypted volumes as generic-password items
  /// whose service and account are both the volume UUID — the "Encrypted
  /// Volume Password" items Finder's and Disk Utility's unlock dialogs
  /// create, and the ones diskmanagementd reads to auto-unlock a disk at
  /// attach time. Reading that entry (instead of a private MountMate-only
  /// copy) lets MountMate reuse a password the user already saved with macOS.
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

  /// Saves a remembered encrypted-volume password.
  ///
  /// When a system "Encrypted Volume Password" entry already exists it is
  /// updated in place — never deleted and re-created — because re-creating
  /// the item would replace its access control list with one that trusts
  /// only MountMate, locking macOS's attach-time auto-unlock out of its own
  /// entry and making it prompt for the password on every plug-in.
  /// MountMate's own entry is used only when no system entry exists.
  func saveRememberedEncryptedVolumePassword(
    _ password: String, volumeUUID: String
  ) -> RememberedPasswordSave {
    let update: [String: Any] = [
      kSecValueData as String: password.data(using: .utf8)!
    ]
    let status = SecItemUpdate(
      encryptedVolumeQuery(volumeUUID: volumeUUID) as CFDictionary,
      update as CFDictionary)

    if status == errSecSuccess {
      // The system entry stays the single source of truth; drop any private
      // entry older versions may have written.
      delete(account: volumeUUID)
      return .systemEntryUpdated
    }
    _ = save(password: password, for: volumeUUID)
    return .privateEntrySaved
  }

  func deleteEncryptedVolumePassword(volumeUUID: String) {
    SecItemDelete(encryptedVolumeQuery(volumeUUID: volumeUUID) as CFDictionary)
  }
}
