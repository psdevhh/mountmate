//  Created by homielab.com

import Foundation

extension Notification.Name {
  static let willManuallyMount = Notification.Name("com.homielab.mountmate.willManuallyMount")
  /// Posted after an encrypted-volume password is saved to the keychain, so
  /// the DiskArbitration session can start listening for disk appearances.
  static let didSaveVolumePassword =
    Notification.Name("com.homielab.mountmate.didSaveVolumePassword")
  /// Posted when an encrypted volume was auto-unlocked on appearance.
  static let didAutoUnlockVolume =
    Notification.Name("com.homielab.mountmate.didAutoUnlockVolume")
}
