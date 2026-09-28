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

  func testEncryptedVolumePasswordRoundTrip() {
    XCTAssertNil(keychain.loadEncryptedVolumePassword(volumeUUID: volumeUUID))

    let status = keychain.saveEncryptedVolumePassword(
      "secret", volumeUUID: volumeUUID, volumeName: "Test Volume")
    XCTAssertEqual(status, errSecSuccess)
    XCTAssertEqual(keychain.loadEncryptedVolumePassword(volumeUUID: volumeUUID), "secret")

    keychain.deleteEncryptedVolumePassword(volumeUUID: volumeUUID)
    XCTAssertNil(keychain.loadEncryptedVolumePassword(volumeUUID: volumeUUID))
  }

  func testSaveEncryptedVolumePasswordOverwritesPreviousValue() {
    keychain.saveEncryptedVolumePassword("old", volumeUUID: volumeUUID, volumeName: "Test")
    keychain.saveEncryptedVolumePassword("new", volumeUUID: volumeUUID, volumeName: "Test")
    XCTAssertEqual(keychain.loadEncryptedVolumePassword(volumeUUID: volumeUUID), "new")
  }

  func testSystemEntryIsIndependentFromLegacyMountMateEntry() {
    // The system-format entry is keyed by the volume UUID itself, while the
    // legacy MountMate entry lives under the app's service name. They must
    // not shadow each other.
    keychain.saveEncryptedVolumePassword("system pw", volumeUUID: volumeUUID, volumeName: "T")
    _ = keychain.save(password: "legacy pw", for: volumeUUID)

    XCTAssertEqual(keychain.loadEncryptedVolumePassword(volumeUUID: volumeUUID), "system pw")
    XCTAssertEqual(keychain.load(account: volumeUUID), "legacy pw")

    keychain.deleteEncryptedVolumePassword(volumeUUID: volumeUUID)
    XCTAssertEqual(keychain.load(account: volumeUUID), "legacy pw")
  }

  func testSavedPassphrasePrefersSystemEntryOverLegacyEntry() {
    let volume = makeVolume(id: volumeUUID)
    XCTAssertNil(DriveManager.savedPassphrase(for: volume))

    _ = keychain.save(password: "legacy pw", for: volumeUUID)
    XCTAssertEqual(DriveManager.savedPassphrase(for: volume)?.passphrase, "legacy pw")
    XCTAssertEqual(DriveManager.savedPassphrase(for: volume)?.source, .mountMate)

    keychain.saveEncryptedVolumePassword("system pw", volumeUUID: volumeUUID, volumeName: "T")
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
}

extension DriveManager.SavedPassphraseSource: Equatable {}
