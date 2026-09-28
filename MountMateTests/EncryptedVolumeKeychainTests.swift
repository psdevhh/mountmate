//  Created by homielab.com

import XCTest
@testable import MountMate

final class EncryptedVolumeKeychainTests: XCTestCase {
  private let keychain = KeychainManager.shared
  // A synthetic UUID that never matches a real volume.
  private let volumeUUID = "00000000-AAAA-BBBB-CCCC-000000000001"

  override func tearDown() {
    keychain.deleteEncryptedVolumePassword(volumeUUID: volumeUUID)
    keychain.delete(account: volumeUUID)
    super.tearDown()
  }

  private func makeVolume(id: String) -> Volume {
    Volume(
      id: id, deviceIdentifier: "disk9s9", diskUUID: nil, name: "Test Volume",
      isMounted: false, mountPoint: nil, freeSpace: nil, totalSize: nil,
      usedSpace: nil, usedBytes: nil, fileSystemType: "apfs", usagePercentage: nil,
      category: .user, isProtected: false, snapshots: [], storageError: nil)
  }

  /// Creates a system-format "Encrypted Volume Password" item directly, the
  /// way macOS's own unlock dialog would.
  private func createSystemEntry(password: String) -> OSStatus {
    var attributes: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: volumeUUID,
      kSecAttrAccount as String: volumeUUID,
      kSecValueData as String: password.data(using: .utf8)!,
    ]
    attributes[kSecAttrLabel as String] = "Test Volume"
    attributes[kSecAttrDescription as String] = "Encrypted Volume Password"
    return SecItemAdd(attributes as CFDictionary, nil)
  }

  private func systemEntryCount() -> Int {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: volumeUUID,
      kSecAttrAccount as String: volumeUUID,
      kSecMatchLimit as String: kSecMatchLimitAll,
      kSecReturnAttributes as String: true,
    ]
    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess else { return 0 }
    return (result as? [[String: Any]])?.count ?? 0
  }

  func testRememberedPasswordSavesPrivateEntryWhenNoSystemEntryExists() {
    let outcome = keychain.saveRememberedEncryptedVolumePassword(
      "secret", volumeUUID: volumeUUID)
    XCTAssertEqual(outcome, .privateEntrySaved)
    XCTAssertNil(keychain.loadEncryptedVolumePassword(volumeUUID: volumeUUID))
    XCTAssertEqual(keychain.load(account: volumeUUID), "secret")
  }

  func testRememberedPasswordUpdatesExistingSystemEntryInPlace() {
    XCTAssertEqual(createSystemEntry(password: "old"), errSecSuccess)

    let outcome = keychain.saveRememberedEncryptedVolumePassword(
      "new", volumeUUID: volumeUUID)
    XCTAssertEqual(outcome, .systemEntryUpdated)
    XCTAssertEqual(keychain.loadEncryptedVolumePassword(volumeUUID: volumeUUID), "new")
    // In place: still exactly one system item, and no private duplicate.
    XCTAssertEqual(systemEntryCount(), 1)
    XCTAssertNil(keychain.load(account: volumeUUID))
  }

  func testRememberedPasswordReplacesStalePrivateEntry() {
    _ = keychain.save(password: "old private", for: volumeUUID)
    XCTAssertEqual(createSystemEntry(password: "system"), errSecSuccess)

    _ = keychain.saveRememberedEncryptedVolumePassword("new", volumeUUID: volumeUUID)
    XCTAssertEqual(keychain.loadEncryptedVolumePassword(volumeUUID: volumeUUID), "new")
    XCTAssertNil(keychain.load(account: volumeUUID))
    XCTAssertEqual(systemEntryCount(), 1)
  }

  func testEncryptedVolumePasswordLoadDeleteRoundTrip() {
    XCTAssertEqual(createSystemEntry(password: "secret"), errSecSuccess)
    XCTAssertEqual(keychain.loadEncryptedVolumePassword(volumeUUID: volumeUUID), "secret")

    keychain.deleteEncryptedVolumePassword(volumeUUID: volumeUUID)
    XCTAssertNil(keychain.loadEncryptedVolumePassword(volumeUUID: volumeUUID))
  }

  func testSavedPassphrasePrefersSystemEntryOverLegacyEntry() {
    let volume = makeVolume(id: volumeUUID)
    XCTAssertNil(DriveManager.savedPassphrase(for: volume))

    _ = keychain.save(password: "legacy pw", for: volumeUUID)
    XCTAssertEqual(DriveManager.savedPassphrase(for: volume)?.passphrase, "legacy pw")
    XCTAssertEqual(DriveManager.savedPassphrase(for: volume)?.source, .mountMate)

    XCTAssertEqual(createSystemEntry(password: "system pw"), errSecSuccess)
    XCTAssertEqual(DriveManager.savedPassphrase(for: volume)?.passphrase, "system pw")
    XCTAssertEqual(DriveManager.savedPassphrase(for: volume)?.source, .system)
  }

  func testLockedVolumeErrorDetection() {
    // diskutil's exact wording when mounting a locked encrypted APFS volume.
    XCTAssertTrue(
      DriveManager.isLockedVolumeErrorMessage(
        "Volume on disk9s2 failed to mount\nThis is an encrypted and locked APFS Volume; use \"diskutil apfs unlockVolume\""
      ))
    XCTAssertFalse(
      DriveManager.isLockedVolumeErrorMessage("Volume on disk9s2 failed to mount"))
    XCTAssertFalse(DriveManager.isLockedVolumeErrorMessage(""))
  }

  func testNotLockedVolumeErrorDetection() {
    // diskutil's wording when unlocking a volume that is already unlocked.
    XCTAssertTrue(
      DriveManager.isVolumeNotLockedErrorMessage(
        "Error unlocking APFS Volume: The given APFS Volume is not locked (-69589)"))
    XCTAssertFalse(
      DriveManager.isVolumeNotLockedErrorMessage(
        "Error unlocking APFS Volume: The pass phrase does not match"))
  }
}

extension KeychainManager.RememberedPasswordSave: Equatable {}
extension DriveManager.SavedPassphraseSource: Equatable {}
