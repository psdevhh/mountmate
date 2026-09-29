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

  func testRememberedPasswordSavesPrivateEntryAndNeverTouchesSystemEntry() {
    // MountMate's "remember password" writes only its private entry; the
    // system entry (if any) must stay untouched — writing it invalidates the
    // access list macOS's attach-time auto-unlock depends on.
    XCTAssertEqual(createSystemEntry(password: "system pw"), errSecSuccess)

    _ = keychain.save(password: "private pw", for: volumeUUID)

    XCTAssertEqual(keychain.loadEncryptedVolumePassword(volumeUUID: volumeUUID), "system pw")
    XCTAssertEqual(keychain.load(account: volumeUUID), "private pw")
  }

  func testEncryptedVolumePasswordLoadDeleteRoundTrip() {
    XCTAssertEqual(createSystemEntry(password: "secret"), errSecSuccess)
    XCTAssertEqual(keychain.loadEncryptedVolumePassword(volumeUUID: volumeUUID), "secret")

    keychain.deleteEncryptedVolumePassword(volumeUUID: volumeUUID)
    XCTAssertNil(keychain.loadEncryptedVolumePassword(volumeUUID: volumeUUID))
  }

  func testSavedPassphrasePrefersPrivateEntryOverSystemEntry() {
    let volume = makeVolume(id: volumeUUID)
    XCTAssertNil(DriveManager.savedPassphrase(for: volume))

    // System entry alone is used as fallback.
    XCTAssertEqual(createSystemEntry(password: "system pw"), errSecSuccess)
    XCTAssertEqual(DriveManager.savedPassphrase(for: volume)?.passphrase, "system pw")
    XCTAssertEqual(DriveManager.savedPassphrase(for: volume)?.source, .system)

    // The private entry wins: reading it never triggers a keychain access
    // prompt.
    _ = keychain.save(password: "private pw", for: volumeUUID)
    XCTAssertEqual(DriveManager.savedPassphrase(for: volume)?.passphrase, "private pw")
    XCTAssertEqual(DriveManager.savedPassphrase(for: volume)?.source, .mountMate)
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

  func testAlreadyUnmountedDetection() {
    func result(_ output: String, stderr: String = "") -> ProcessResult {
      ProcessResult(stdout: output, stderr: stderr, exitCode: 1, timedOut: false)
    }
    XCTAssertTrue(result("disk7s1 was already unmounted").isAlreadyUnmounted)
    XCTAssertTrue(result("volume is not mounted").isAlreadyUnmounted)
    XCTAssertTrue(result("", stderr: "disk7s1 was already unmounted").isAlreadyUnmounted)
    XCTAssertFalse(result("resource busy").isAlreadyUnmounted)
  }

  func testProcessResultErrorMessageWording() {
    XCTAssertEqual(
      ProcessResult(stdout: "", stderr: "", exitCode: nil, timedOut: true).errorMessage,
      "The operation timed out after 15 seconds.")
    XCTAssertEqual(
      ProcessResult(stdout: "", stderr: "", exitCode: 6, timedOut: false).errorMessage,
      "diskutil exited with code 6.")
    XCTAssertEqual(
      ProcessResult(stdout: "", stderr: "boom", exitCode: 1, timedOut: false).errorMessage,
      "boom")
  }

  func testHasAnyRememberedPasswordsReflectsSavedEntries() {
    _ = keychain.save(password: "x", for: volumeUUID)
    XCTAssertTrue(keychain.hasAnyRememberedPasswords())
  }
}
