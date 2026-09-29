//  Created by homielab.com

import XCTest

@testable import MountMate

/// End-to-end test of appearance-based auto-unlock: creates a real
/// encrypted APFS volume inside a disk image, saves its password as
/// MountMate's private keychain entry, then detaches and re-attaches the
/// image. The re-attach fires the same DiskArbitration disk-appeared event
/// a physical plug-in does, and the app must unlock the volume on its own.
///
/// Opt in with MM_AUTO_UNLOCK_E2E=1 (image creation and attach take a few
/// seconds, so it is skipped by default).
final class AutoUnlockOnAppearTests: XCTestCase {
  // Unique per run so leftovers from crashed runs cannot collide.
  private let runID = UUID().uuidString.prefix(8).lowercased()
  private var holderName: String { "MMAU-\(runID)" }
  private var volumeName: String { "MMAU Vol \(runID)" }
  private let password = "mountmate-e2e-pw"

  private var imagePath: String!
  private var wholeDisk: String!
  private var volumeUUID: String!

  private func run(_ executable: String, _ arguments: [String]) -> (code: Int32, out: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe
    try? process.run()
    // Drain concurrently: reading only after exit deadlocks once output
    // fills the pipe buffer (e.g. `diskutil list -plist` on busy systems).
    var out = Data()
    let drained = DispatchGroup()
    drained.enter()
    DispatchQueue.global().async {
      out = pipe.fileHandleForReading.readDataToEndOfFile()
      drained.leave()
    }
    process.waitUntilExit()
    drained.wait()
    return (process.terminationStatus, String(data: out, encoding: .utf8) ?? "")
  }

  /// `diskutil list -plist` as a dictionary.
  private func diskList() -> [String: Any] {
    let result = run("/usr/sbin/diskutil", ["list", "-plist"])
    guard let data = result.out.data(using: .utf8),
      let plist = try? PropertyListSerialization.propertyList(
        from: data, options: [], format: nil) as? [String: Any]
    else { return [:] }
    return plist
  }

  /// Finds the synthesized APFS container disk (by the presence of the
  /// holder or encrypted volume) and the encrypted volume's UUID.
  private func locate() -> (container: String?, volumeUUID: String?) {
    guard let disks = diskList()["AllDisksAndPartitions"] as? [[String: Any]] else {
      return (nil, nil)
    }
    for disk in disks {
      guard let volumes = disk["APFSVolumes"] as? [[String: Any]] else { continue }
      let hasHolder = volumes.contains { ($0["VolumeName"] as? String) == holderName }
      let encrypted = volumes.first { ($0["VolumeName"] as? String) == volumeName }
      if hasHolder || encrypted != nil {
        return (disk["DeviceIdentifier"] as? String, encrypted?["VolumeUUID"] as? String)
      }
    }
    return (nil, nil)
  }

  override func setUpWithError() throws {
    guard ProcessInfo.processInfo.environment["MM_AUTO_UNLOCK_E2E"] == "1" else {
      throw XCTSkip("Set MM_AUTO_UNLOCK_E2E=1 to run this test")
    }

    imagePath = NSTemporaryDirectory() + "mm-auto-unlock-\(UUID().uuidString).dmg"
    let create = run(
      "/usr/sbin/diskutil",
      ["image", "create", "blank", "--size", "1g", "--fs", "APFS", "--volumeName", holderName,
       imagePath])
    XCTAssertEqual(create.code, 0, "image create failed: \(create.out)")
    XCTAssertEqual(run("/usr/bin/hdiutil", ["attach", imagePath]).code, 0, "attach failed")

    let located = locate()
    XCTAssertNotNil(located.container, "holder volume not found after attach")

    let add = run(
      "/usr/sbin/diskutil",
      ["apfs", "addVolume", located.container ?? "", "APFS", volumeName, "-passphrase", password])
    XCTAssertEqual(add.code, 0, "addVolume failed: \(add.out)")

    volumeUUID = locate().volumeUUID
    XCTAssertNotNil(volumeUUID, "encrypted volume not found after addVolume")

    // Lock and detach BEFORE saving the password, so appearance sweeps
    // cannot unlock the volume mid-setup. Detaching the whole disk is what
    // discards the encryption key — the state a fresh plug-in presents.
    XCTAssertEqual(
      run("/usr/sbin/diskutil", ["apfs", "lockVolume", volumeUUID]).code, 0, "lockVolume failed")
    let parentDisk = run("/usr/sbin/diskutil", ["info", "-plist", volumeUUID!]).out
      .data(using: .utf8)
      .flatMap {
        try? PropertyListSerialization.propertyList(from: $0, options: [], format: nil)
          as? [String: Any]
      }?["ParentWholeDisk"] as? String
    XCTAssertNotNil(parentDisk, "no parent whole disk for \(volumeUUID ?? "?")")
    wholeDisk = parentDisk
    XCTAssertEqual(
      run("/usr/bin/hdiutil", ["detach", parentDisk ?? ""]).code, 0, "detach failed")

    // Save the password the way MountMate's "remember password" does.
    _ = KeychainManager.shared.save(password: password, for: volumeUUID)
  }

  override func tearDown() {
    if let volumeUUID {
      KeychainManager.shared.delete(account: volumeUUID)
      KeychainManager.shared.deleteEncryptedVolumePassword(volumeUUID: volumeUUID)
    }
    if let imagePath {
      _ = run("/usr/bin/hdiutil", ["detach", imagePath])
      try? FileManager.default.removeItem(atPath: imagePath)
    }
  }

  func testAttachAutoUnlocksVolume() throws {
    let unlocked = XCTNSNotificationExpectation(name: .didAutoUnlockVolume, object: nil)
    XCTAssertEqual(run("/usr/bin/hdiutil", ["attach", imagePath]).code, 0, "reattach failed")
    wait(for: [unlocked], timeout: 20)

    // The volume must be unlocked without any user interaction. Whether the
    // OS then auto-mounts it is governed by the existing mount-blocker
    // rules and is not this feature's concern.
    let info = run("/usr/sbin/diskutil", ["info", volumeUUID]).out
    XCTAssertTrue(
      info.range(of: "Locked:\\s+No", options: .regularExpression) != nil,
      "volume not unlocked:\n\(info)")
  }
}
