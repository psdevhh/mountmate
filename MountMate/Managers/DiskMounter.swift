//  Created by homielab.com

import Combine
import DiskArbitration
import Foundation
import IOKit

class DiskMounter: ObservableObject {
  @Published var blockUSBAutoMount: Bool = UserDefaults.standard.bool(forKey: "blockUSBAutoMount")
  {
    didSet {
      UserDefaults.standard.set(blockUSBAutoMount, forKey: "blockUSBAutoMount")
      updateSessionState()
    }
  }

  private var session: DASession?
  private var manualMountApprovals: [String: Date] = [:]
  private let manualMountApprovalLock = NSLock()
  private var cancellables = Set<AnyCancellable>()
  /// Guards the launch-time cleanup so it runs once per app launch even when
  /// the session is restarted.
  private var hasPerformedStartupMaintenance = false

  /// IOKit media-arrival notifications: unlike DiskArbitration's
  /// disk-appeared events, these fire for locked encrypted volumes too.
  private var ioNotificationPort: IONotificationPortRef?
  private var ioMediaIterator: io_iterator_t = 0
  private let sweepLock = NSLock()
  private var isSweepingLockedVolumes = false
  private var isSweepPending = false

  init() {
    NotificationCenter.default.addObserver(
      self, selector: #selector(handleWillMount), name: .willManuallyMount, object: nil)

    // Saving the first remembered volume password enables appearance-based
    // auto-unlock, which needs the DiskArbitration session to be running.
    NotificationCenter.default.addObserver(
      self, selector: #selector(handleSavedPassword), name: .didSaveVolumePassword,
      object: nil)

    PersistenceManager.shared.$blockedVolumes
      .receive(on: DispatchQueue.main)
      .sink { [weak self] _ in self?.updateSessionState() }
      .store(in: &cancellables)

    updateSessionState()
  }

  deinit {
    NotificationCenter.default.removeObserver(self)
    stopDiskArbitration()
  }

  @objc private func handleSavedPassword(_ notification: Notification) {
    updateSessionState()
  }

  private func updateSessionState() {
    let shouldBeActive =
      blockUSBAutoMount
      || !PersistenceManager.shared.blockedVolumes.isEmpty
      || KeychainManager.shared.hasAnyRememberedPasswords()
    if shouldBeActive && session == nil {
      startDiskArbitration()
    } else if !shouldBeActive && session != nil {
      stopDiskArbitration()
    }
  }

  @objc private func handleWillMount(notification: Notification) {
    guard let identifier = notification.userInfo?["deviceIdentifier"] as? String,
      !identifier.isEmpty
    else { return }

    let key = identifier.lowercased()
    let expiration = Date().addingTimeInterval(5.0)
    manualMountApprovalLock.lock()
    manualMountApprovals[key] = expiration
    manualMountApprovalLock.unlock()

    DispatchQueue.main.asyncAfter(deadline: .now() + 5.0) { [weak self] in
      guard let self else { return }
      self.manualMountApprovalLock.lock()
      if self.manualMountApprovals[key] == expiration {
        self.manualMountApprovals.removeValue(forKey: key)
      }
      self.manualMountApprovalLock.unlock()
    }
  }

  private func consumeManualMountApproval(
    bsdName: String?, volumeUUID: String?, diskUUID: String?
  ) -> Bool {
    let identifiers = [bsdName, volumeUUID, diskUUID]
      .compactMap { $0?.lowercased() }
    guard !identifiers.isEmpty else { return false }

    let now = Date()
    manualMountApprovalLock.lock()
    defer { manualMountApprovalLock.unlock() }
    manualMountApprovals = manualMountApprovals.filter { $0.value > now }

    for identifier in identifiers {
      if manualMountApprovals.removeValue(forKey: identifier) != nil {
        return true
      }
    }
    return false
  }

  private func startDiskArbitration() {
    guard session == nil else { return }
    print("✅ Starting Disk Arbitration session...")
    session = DASessionCreate(kCFAllocatorDefault)
    guard let session = session else { return }

    let context = Unmanaged.passUnretained(self).toOpaque()

    let mountCallback: DADiskMountApprovalCallback = { (disk, context) -> Unmanaged<DADissenter>? in
      guard let context = context else { return nil }
      let this = Unmanaged<DiskMounter>.fromOpaque(context).takeUnretainedValue()
      let bsdName = DADiskGetBSDName(disk).map({ String(cString: $0) })

      guard let desc = DADiskCopyDescription(disk) else { return nil }
      let description = desc as! [String: Any]

      // Approve non-physical media (disk images).
      if let model = description[kDADiskDescriptionDeviceModelKey as String] as? String,
        model == "Disk Image"
      {
        return nil
      }

      // Specific volume is in the blocked list.
      let rawVolumeUUID = description[kDADiskDescriptionVolumeUUIDKey as String]
      let rawDiskUUID = description[kDADiskDescriptionMediaUUIDKey as String]

      var volumeUUIDString: String?
      var diskUUIDString: String?

      if let volCF = rawVolumeUUID as CFTypeRef?, CFGetTypeID(volCF) == CFUUIDGetTypeID() {
        volumeUUIDString = CFUUIDCreateString(nil, (volCF as! CFUUID)) as String
      }
      if let diskCF = rawDiskUUID as CFTypeRef?, CFGetTypeID(diskCF) == CFUUIDGetTypeID() {
        diskUUIDString = CFUUIDCreateString(nil, (diskCF as! CFUUID)) as String
      }

      // Only mount requests explicitly initiated by MountMate bypass the
      // runtime block. Disk Arbitration does not identify the source of a
      // request from Finder, Terminal, or the OS.
      if this.consumeManualMountApproval(
        bsdName: bsdName, volumeUUID: volumeUUIDString, diskUUID: diskUUIDString)
      {
        return nil
      }

      var shouldBlock = false

      // Global USB block.
      // kDADiskDescriptionDeviceProtocolKey ("DADeviceProtocol") is rarely
      // populated at the volume level. The reliable key is "BusProtocol",
      // which lives in the whole-disk description. Walk up to the whole disk
      // and read its description when the volume-level one lacks bus info.
      if this.blockUSBAutoMount {
        // Try the volume-level description first.
        var busProtocol = description["BusProtocol"] as? String

        // Fall back to the whole-disk (parent) description if not present.
        if busProtocol == nil, let wholeDisk = DADiskCopyWholeDisk(disk) {
          if let parentDesc = DADiskCopyDescription(wholeDisk) {
            let parentDict = parentDesc as! [String: Any]
            busProtocol = parentDict["BusProtocol"] as? String
          }
        }

        // Block USB drives and SD cards. "BusProtocol" values observed on
        // macOS include "USB", "SD", "Bluetooth", "Thunderbolt", etc.
        // The feature is named "Block USB Auto-Mount" so scope to USB/SD.
        if let proto = busProtocol,
          proto.caseInsensitiveCompare("USB") == .orderedSame
            || proto.caseInsensitiveCompare("SD") == .orderedSame
        {
          shouldBlock = true
        }
      }

      if let volUUID = volumeUUIDString {
        let dUUID = diskUUIDString ?? "NONE"
        let compositeId = "\(dUUID)-\(volUUID)"
        if PersistenceManager.shared.blockedVolumes.contains(where: { $0.id == compositeId }) {
          shouldBlock = true
        }
      }

      if shouldBlock {
        print("🚫 Dissenting auto-mount for \(bsdName ?? "unknown volume").")
        let dissenter = DADissenterCreate(kCFAllocatorDefault, DAReturn(kDAReturnNotPermitted), nil)
        return Unmanaged.passRetained(dissenter)
      }

      // Approved.
      return nil
    }

    let matching: [String: Any] = [kDADiskDescriptionVolumeMountableKey as String: kCFBooleanTrue!]
    DARegisterDiskMountApprovalCallback(session, matching as CFDictionary, mountCallback, context)

    DASessionSetDispatchQueue(session, DispatchQueue.main)

    startMediaNotifications()
    scheduleStartupMaintenance()
  }

  /// Watches for media arrivals via IOKit. DiskArbitration's disk-appeared
  /// events never fire for locked encrypted volumes — the exact volumes
  /// appearance-based auto-unlock is for — so the notification has to come
  /// from the IOKit level, where every IOMedia publish (a plugged disk, an
  /// attached image) is visible.
  private func startMediaNotifications() {
    guard ioNotificationPort == nil else { return }
    guard let port = IONotificationPortCreate(kIOMainPortDefault) else { return }
    ioNotificationPort = port
    // Dispatch-queue delivery: unlike a runloop source it does not depend on
    // the main runloop running in a particular mode.
    IONotificationPortSetDispatchQueue(port, DispatchQueue.main)

    let refcon = Unmanaged.passUnretained(self).toOpaque()
    let callback: IOServiceMatchingCallback = { refcon, iterator in
      guard let refcon else { return }
      let this = Unmanaged<DiskMounter>.fromOpaque(refcon).takeUnretainedValue()
      // Drain the iterator so the notification re-arms for future arrivals.
      while IOIteratorNext(iterator) != 0 {}
      this.scheduleLockedVolumeSweep()
    }

    var iterator = io_iterator_t(0)
    let matching = IOServiceMatching("IOMedia")
    guard
      IOServiceAddMatchingNotification(
        port, kIOFirstPublishNotification, matching, callback, refcon, &iterator)
        == KERN_SUCCESS
    else {
      stopMediaNotifications()
      return
    }
    ioMediaIterator = iterator

    // The iterator arrives pre-armed with all already-present media; drain
    // it so only future arrivals notify, then sweep once for the current
    // state (covers a drive plugged in before the app launched).
    while IOIteratorNext(ioMediaIterator) != 0 {}
    scheduleLockedVolumeSweep()
  }

  private func stopMediaNotifications() {
    guard let port = ioNotificationPort else { return }
    IONotificationPortSetDispatchQueue(port, nil)
    IONotificationPortDestroy(port)
    ioNotificationPort = nil
    if ioMediaIterator != 0 {
      IOObjectRelease(ioMediaIterator)
      ioMediaIterator = 0
    }
  }

  /// Coalesces bursts of media arrivals (a disk publishes several IOMedia
  /// objects) into a single sweep shortly after the bus settles.
  private func scheduleLockedVolumeSweep() {
    DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 0.4) { [weak self] in
      self?.sweepLockedVolumes()
    }
  }

  /// Unlocks every encrypted volume that is present, locked, and has a
  /// remembered password — without mounting it. Mounting stays a deliberate
  /// act (user click or the OS automount, subject to the blockers).
  ///
  /// Unlocking immediately also outruns macOS's attach-time unlock agent:
  /// on macOS versions where that agent cannot silently read the keychain
  /// entry (entries recreated or touched by third-party apps lose the
  /// agent's access grant), it would otherwise put a password dialog on
  /// screen at every plug-in. Once the volume is unlocked, the agent has
  /// nothing to ask about.
  private func sweepLockedVolumes() {
    sweepLock.lock()
    if isSweepingLockedVolumes {
      // A sweep is in flight; remember to run again afterwards so bursts of
      // media arrivals are never dropped.
      isSweepPending = true
      sweepLock.unlock()
      return
    }
    isSweepingLockedVolumes = true
    isSweepPending = false
    sweepLock.unlock()
    defer {
      sweepLock.lock()
      let rerun = isSweepPending
      isSweepPending = false
      isSweepingLockedVolumes = false
      sweepLock.unlock()
      if rerun {
        scheduleLockedVolumeSweep()
      }
    }

    let list = runProcess(
      executable: "/usr/sbin/diskutil", arguments: ["list", "-plist"], timeout: 30)
    guard let data = list.stdout.data(using: .utf8),
      let plist = try? PropertyListSerialization.propertyList(
        from: data, options: [], format: nil) as? [String: Any],
      let disks = plist["AllDisksAndPartitions"] as? [[String: Any]]
    else {
      return
    }

    for disk in disks {
      let volumes =
        (disk["APFSVolumes"] as? [[String: Any]] ?? []) + (disk["Partitions"] as? [[String: Any]]
          ?? [])
      for volume in volumes {
        guard let volumeUUID = volume["VolumeUUID"] as? String,
          let passphrase = DriveManager.savedPassphrase(volumeUUID: volumeUUID)
        else { continue }

        // An unlock attempt on a volume that is not locked (or not
        // encrypted) fails harmlessly; -nomount keeps mounting a deliberate
        // act regardless.
        let unlock = runProcess(
          executable: "/usr/sbin/diskutil",
          arguments: ["apfs", "unlockVolume", volumeUUID, "-stdinpassphrase", "-nomount"],
          input: Data(passphrase.utf8))
        if unlock.succeeded {
          print("🔓 Auto-unlocked encrypted volume \(volumeUUID) on appearance.")
          NotificationCenter.default.post(
            name: .didAutoUnlockVolume, object: nil, userInfo: ["volumeUUID": volumeUUID])
          DispatchQueue.main.async {
            DriveManager.shared.refreshDrives(qos: .utility)
          }
        }
        // Failures stay silent: the volume may not be locked after all, and
        // stale passwords are surfaced properly by user-initiated mounts.
      }
    }
  }

  /// Runs once per app launch, shortly after the Disk Arbitration session
  /// starts: unmounts blocked volumes the OS mounted before MountMate was
  /// running. Mount approval callbacks cannot run before a user-session app
  /// launches, so this is best-effort cleanup for volumes mounted at login.
  private func scheduleStartupMaintenance() {
    DispatchQueue.main.asyncAfter(deadline: .now() + 5.0) { [weak self] in
      guard let self, self.session != nil, !self.hasPerformedStartupMaintenance else { return }
      self.hasPerformedStartupMaintenance = true

      // Snapshot the main-thread-bound lists before doing the diskutil work
      // on a background queue.
      let blockedInfos = PersistenceManager.shared.blockedVolumes
      self.unmountBlockedVolumes(blockedInfos)
    }
  }

  /// Unmounts blocked volumes that are already mounted — typically because
  /// the OS mounted them before MountMate's user-session callback was active.
  /// A few retries absorb transient busyness (Spotlight indexing right after
  /// login). Never forces: a persistently busy volume is left mounted.
  private func unmountBlockedVolumes(_ blockedInfos: [ManagedVolumeInfo]) {
    DispatchQueue.global(qos: .utility).async {
      for info in blockedInfos {
        guard
          let volumeUUID = PersistenceManager.normalizedSystemVolumeUUID(info.volumeUUID)
        else { continue }

        let infoResult = runProcess(
          executable: "/usr/sbin/diskutil", arguments: ["info", "-plist", volumeUUID])
        guard infoResult.succeeded,
          let data = infoResult.stdout.data(using: .utf8),
          let plist = try? PropertyListSerialization.propertyList(
            from: data, options: [], format: nil) as? [String: Any],
          let device = plist["DeviceIdentifier"] as? String,
          let mountPoint = plist["MountPoint"] as? String
        else { continue }

        let trimmedMountPoint = mountPoint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedMountPoint.isEmpty,
          trimmedMountPoint.caseInsensitiveCompare("Not Mounted") != .orderedSame
        else { continue }

        for attempt in 1...3 {
          let result = runProcess(
            executable: "/usr/sbin/diskutil", arguments: ["unmount", device])
          if result.succeeded {
            print("🚫 Unmounted blocked volume “\(info.name)” after startup.")
            break
          }
          if result.isAlreadyUnmounted {
            print("ℹ️ Blocked volume “\(info.name)” was already unmounted.")
            break
          }
          print(
            "⚠️ Could not unmount blocked volume “\(info.name)” (attempt \(attempt)/3): \(result.stderr)"
          )
          if attempt < 3 {
            Thread.sleep(forTimeInterval: 3.0)
          }
        }
      }
    }
  }

  private func stopDiskArbitration() {
    guard let session = session else { return }
    DASessionSetDispatchQueue(session, nil)
    stopMediaNotifications()
    manualMountApprovalLock.lock()
    manualMountApprovals.removeAll()
    manualMountApprovalLock.unlock()
    self.session = nil
  }
}
