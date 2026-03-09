import 'dart:io';
import 'package:win32_registry/win32_registry.dart';

class StartupManager {
  static const String _appName = "x2y_AV_Ultimate";

  static Future<void> setStartup(bool enable) async {
    try {
      final key = Registry.openPath(
        RegistryHive.currentUser, 
        path: r'Software\Microsoft\Windows\CurrentVersion\Run',
        desiredAccessRights: AccessRights.allAccess
      );

      if (enable) {
        // Get path to current executable
        String exePath = Platform.resolvedExecutable;
        key.createValue(RegistryValue(_appName, RegistryValueType.string, exePath));
      } else {
        key.deleteValue(_appName);
      }
      
      key.close();
    } catch (e) {
      print("Startup Registry Error: $e");
    }
  }

  static Future<bool> isStartupEnabled() async {
    try {
      final key = Registry.openPath(
        RegistryHive.currentUser, 
        path: r'Software\Microsoft\Windows\CurrentVersion\Run',
      );
      final val = key.getValue(_appName);
      key.close();
      return val != null;
    } catch (e) {
      return false;
    }
  }
}