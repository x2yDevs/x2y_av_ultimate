import 'dart:io';
import 'package:win32_registry/win32_registry.dart';
import 'package:path_provider/path_provider.dart';
import 'package:path/path.dart' as p;

class PersistenceItem {
  final String name;
  final String path;
  final String type; // Registry or Folder

  PersistenceItem(this.name, this.path, this.type);
}

class PersistenceAuditor {
  Future<List<PersistenceItem>> runAudit() async {
    List<PersistenceItem> items = [];

    // 1. Registry: HKCU Run
    try {
      final key = Registry.openPath(RegistryHive.currentUser, path: r'Software\Microsoft\Windows\CurrentVersion\Run');
      for (var val in key.values) {
        items.add(PersistenceItem(val.name, val.data.toString(), "Registry [HKCU]"));
      }
      key.close();
    } catch (_) {}

    // 2. Registry: HKLM Run (Requires Admin)
    try {
      final key = Registry.openPath(RegistryHive.localMachine, path: r'Software\Microsoft\Windows\CurrentVersion\Run');
      for (var val in key.values) {
        items.add(PersistenceItem(val.name, val.data.toString(), "Registry [HKLM]"));
      }
      key.close();
    } catch (_) {}

    // 3. Startup Folder (Real Path Check)
    try {
      // Common Startup path construction
      final appData = Platform.environment['APPDATA'];
      if (appData != null) {
        final startupPath = p.join(appData, r'Microsoft\Windows\Start Menu\Programs\Startup');
        final dir = Directory(startupPath);
        
        if (await dir.exists()) {
          await for (var entity in dir.list()) {
            if (entity is File) {
              items.add(PersistenceItem(p.basename(entity.path), entity.path, "Startup Folder"));
            }
          }
        }
      }
    } catch (_) {}

    return items;
  }
}