import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:x2y_av_ultimate/core/notification_manager.dart';

class QuarantineManager {
  static const String _ext = ".x2y_quarantine";

  Future<Directory> get _quarantineDir async {
    final appDir = await getApplicationSupportDirectory();
    final dir = Directory(p.join(appDir.path, 'Quarantine_Vault'));
    if (!await dir.exists()) await dir.create();
    return dir;
  }

  Future<void> quarantineFile(File file) async {
    try {
      final qDir = await _quarantineDir;
      final filename = p.basename(file.path);
      // We encode the original path in the filename for restoration simply: 
      // OriginalName_ORIGINALPATHHASH.x2y_quarantine (In production use a DB map)
      final safeName = "$filename$_ext";
      final targetPath = p.join(qDir.path, safeName);

      // Move and rename
      await file.rename(targetPath);
      
      X2yNotifier.show(
        "Threat Quarantined", 
        "File $filename has been isolated to prevent execution.",
        isCritical: true
      );
    } catch (e) {
      print("Quarantine Error: $e");
    }
  }

  Future<List<File>> getQuarantinedFiles() async {
    final dir = await _quarantineDir;
    return dir.listSync().whereType<File>().toList();
  }

  Future<void> restoreFile(File qFile) async {
    // Basic restore logic
    final downloads = await getDownloadsDirectory(); // Restore to downloads for safety
    final originalName = p.basename(qFile.path).replaceAll(_ext, '');
    final target = p.join(downloads!.path, "Restored_$originalName");
    
    await qFile.rename(target);
    X2yNotifier.show("File Restored", "$originalName restored to Downloads folder.");
  }

  Future<void> deletePermanently(File qFile) async {
    if(await qFile.exists()) {
      await qFile.delete();
      X2yNotifier.show("File Incinerated", "The threat has been permanently removed.");
    }
  }
}