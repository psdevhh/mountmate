//  Created by homielab.com

import XCTest

@testable import MountMate

/// End-to-end test of the encrypted-volume recovery flow against a real
/// locked APFS volume. Opt in by attaching a locked, encrypted APFS volume
/// and setting two environment variables before running tests:
///
///     MM_LOCKED_VOLUME_UUID=<volume UUID> \
///     MM_LOCKED_VOLUME_PASS=<its password> \
///     xcodebuild test -only-testing:MountMateTests/LockedVolumeUnlockIntegrationTests
///
/// The test saves the password in the system "Encrypted Volume Password"
/// keychain format, triggers the regular mount flow (which fails on a locked
/// volume and would previously show the password prompt), and asserts the
/// volume ends up mounted without any prompt being presented. Skipped
/// entirely when the environment variables are absent.
final class LockedVolumeUnlockIntegrationTests: XCTestCase {
  private var volumeUUID: String!
  private var passphrase: String!

  override func setUpWithError() throws {
    let env = ProcessInfo.processInfo.environment
    guard let uuid = env["MM_LOCKED_VOLUME_UUID"], !uuid.isEmpty,
      let pass = env["MM_LOCKED_VOLUME_PASS"], !pass.isEmpty
    else {
      throw XCTSkip(
        "Set MM_LOCKED_VOLUME_UUID and MM_LOCKED_VOLUME_PASS to a locked encrypted APFS volume to run this test."
      )
    }
    volumeUUID = uuid
    passphrase = pass

    KeychainManager.shared.deleteEncryptedVolumePassword(volumeUUID: uuid)
    KeychainManager.shared.delete(account: uuid)
  }

  override func tearDown() {
    if let volumeUUID {
      KeychainManager.shared.deleteEncryptedVolumePassword(volumeUUID: volumeUUID)
      KeychainManager.shared.delete(account: volumeUUID)
    }
  }

  func testMountUnlocksVolumeWithSavedSystemKeychainPasswordWithoutPrompting() throws {
    // The volume must start out locked and unmounted.
    let before = try Self.volumeInfo(volumeUUID)
    XCTAssertFalse(Self.isVolumeMounted(before))

    // Simulate "remember password": the system-format entry the OS's own
    // unlock dialog would create.
    let status = KeychainManager.shared.saveEncryptedVolumePassword(
      passphrase, volumeUUID: volumeUUID, volumeName: (before["VolumeName"] as? String) ?? "")
    XCTAssertEqual(status, errSecSuccess)

    let volume = Volume(
      id: volumeUUID, deviceIdentifier: before["DeviceIdentifier"] as! String,
      diskUUID: nil, name: (before["VolumeName"] as? String) ?? volumeUUID,
      isMounted: false, mountPoint: nil, freeSpace: nil, totalSize: nil, usedSpace: nil,
      usedBytes: nil, fileSystemType: "apfs", usagePercentage: nil, category: .user,
      isProtected: false, snapshots: [], storageError: nil)

    DriveManager.shared.mount(volume: volume)

    // Poll while keeping the main run loop (and therefore MountMate's main
    // queue hops, e.g. the unlock recovery) serviced.
    var isMounted = false
    let deadline = Date().addingTimeInterval(60)
    while Date() < deadline {
      RunLoop.current.run(until: Date().addingTimeInterval(0.5))
      if let info = try? Self.volumeInfo(volumeUUID), Self.isVolumeMounted(info) {
        isMounted = true
        break
      }
    }
    XCTAssertTrue(
      isMounted, "volume was not mounted by the keychain-based recovery in time")

    // The prompt must never have been presented: it is driven by
    // userActionError, which must stay nil for the whole recovery.
    XCTAssertNil(DriveManager.shared.userActionError)
  }

  /// `diskutil info -plist` reports mounting via the "Mounted" boolean on
  /// some macOS versions and only via a non-empty "MountPoint" on others.
  private static func isVolumeMounted(_ info: [String: Any]) -> Bool {
    if let mounted = info["Mounted"] as? Bool { return mounted }
    if let mountPoint = info["MountPoint"] as? String { return !mountPoint.isEmpty }
    return false
  }

  /// Runs `diskutil info -plist` for a volume identifier and parses it.
  private static func volumeInfo(_ uuid: String) throws -> [String: Any] {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/sbin/diskutil")
    process.arguments = ["info", "-plist", uuid]
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = Pipe()
    try process.run()
    process.waitUntilExit()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    return try XCTUnwrap(
      PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
      "diskutil info returned no plist for \(uuid)")
  }
}
