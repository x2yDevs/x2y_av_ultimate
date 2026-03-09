import 'dart:io';
import 'dart:async';
import 'package:crypto/crypto.dart';
import 'package:process_run/shell.dart';
import 'package:path/path.dart' as p;
import 'package:x2y_av_ultimate/services/threat_intelligence.dart';

class AVCore {
  final _logController = StreamController<String>.broadcast();
  Stream<String> get activityLog => _logController.stream;

  // Global Exclusion List (Managed by Settings)
  static List<String> exclusionPaths = [];

  // --- Hashing Logic ---
  Future<String> calculateHash(File file) async {
    try {
      if (!file.existsSync()) return "";
      
      // Optimization: Skip files larger than 100MB for real-time performance
      // In a strict mode, we would scan headers, but for general use this prevents UI freeze
      if (await file.length() > 100 * 1024 * 1024) return "SKIPPED_LARGE_FILE";
      
      var input = file.openRead();
      var digest = await sha256.bind(input).first;
      return digest.toString();
    } catch (e) {
      return ""; // File locked or access denied
    }
  }

  // --- Core Inspection ---
  Future<bool> inspectFile(File file) async {
    // 1. Check Exclusions
    if (exclusionPaths.any((ex) => file.path.startsWith(ex))) return true;

    String hash = await calculateHash(file);
    if (hash.isEmpty || hash == "SKIPPED_LARGE_FILE") return true;

    // 2. Local DB Check (Fast)
    bool isLocalThreat = await ThreatIntelligence.instance.isThreat(hash);
    if (isLocalThreat) {
      await _executeContainment(file, hash, "LOCAL_DB_MATCH");
      return false; // THREAT FOUND
    }

    // 3. Cloud Check (Smart Filtering)
    if (_isSuspiciousSystemFile(file.path)) {
       bool isCloudThreat = await ThreatIntelligence.instance.checkCloudAPI(hash);
       if (isCloudThreat) {
         await _executeContainment(file, hash, "CLOUD_INTEL_MATCH");
         return false; // THREAT FOUND
       }
    }
    return true; // SAFE
  }

  bool _isSuspiciousSystemFile(String filePath) {
    final ext = p.extension(filePath).toLowerCase();
    const highRiskExtensions = {
      '.exe', '.dll', '.scr', '.com', '.bat', '.ps1', '.vbs', '.js', '.msi'
    };
    return highRiskExtensions.contains(ext);
  }

  Future<void> _executeContainment(File file, String hash, String source) async {
    String name = p.basename(file.path);
    _logController.add("!!! BLOCKING: $name [$source] !!!");
    
    // A. Kill Process
    try {
      var shell = Shell();
      await shell.run('taskkill /F /IM "$name"');
    } catch (_) {}

    // B. Quarantine/Delete
    try {
      if (file.existsSync()) {
        // Destroy content first
        await file.writeAsString("QUARANTINED_X2Y_$hash");
        await file.delete();
      }
    } catch (e) {
      _logController.add("Delete Failed: Access Denied");
    }
  }

  // --- Bulk Scanning Algorithms ---
  
  // 1. Quick Scan: Windows, System32, User Root
  Stream<ScanStatus> runQuickScan() async* {
    List<Directory> targets = [];
    
    String? winDir = Platform.environment['SystemRoot'];
    if (winDir != null) targets.add(Directory(winDir));
    
    String? userProfile = Platform.environment['USERPROFILE'];
    if (userProfile != null) {
        targets.add(Directory(p.join(userProfile, 'Downloads')));
        targets.add(Directory(p.join(userProfile, 'Desktop')));
        targets.add(Directory(p.join(userProfile, 'AppData', 'Local', 'Temp')));
    }

    int totalEstimated = 5000; 
    int processed = 0;

    for (var dir in targets) {
      if (!dir.existsSync()) continue;
      try {
        var files = dir.listSync();
        for (var entity in files) {
          if (entity is File) {
             processed++;
             // Yield status updates
             yield ScanStatus(entity.path, processed, totalEstimated);
             await inspectFile(entity);
          }
        }
      } catch (_) {}
    }
  }

  // 2. Full Scan: Recursive from Root Drive
  Stream<ScanStatus> runFullScan() async* {
    String? drive = Platform.environment['SystemDrive'] ?? "C:";
    Directory root = Directory("$drive\\");
    
    int totalEstimated = 300000; // Rough average
    int processed = 0;

    // Recursive stream
    Stream<FileSystemEntity> fileStream = root.list(recursive: true, followLinks: false);

    await for (final entity in fileStream.handleError((e) {})) { 
      if (entity is File) {
        processed++;
        // Throttle UI updates to prevent lag (update every 20 files)
        if (processed % 20 == 0) {
           yield ScanStatus(entity.path, processed, totalEstimated);
        }
        await inspectFile(entity);
      }
    }
  }

  // 3. Custom Path Scan (Single File or Specific Folder)
  Stream<ScanStatus> runCustomPathScan(String path) async* {
    FileSystemEntityType type = await FileSystemEntity.type(path);
    
    if (type == FileSystemEntityType.file) {
       // Single File
       yield ScanStatus(path, 1, 1);
       await inspectFile(File(path));
    
    } else if (type == FileSystemEntityType.directory) {
       // Directory (Recursive)
       Directory dir = Directory(path);
       
       // Pre-calculate count for progress bar (Catch permission errors)
       int count = 0;
       try {
         count = dir.listSync(recursive: true).length;
       } catch(_) {
         count = 100; // Fallback if enumeration fails
       }
       if(count == 0) count = 1;

       int processed = 0;
       Stream<FileSystemEntity> stream = dir.list(recursive: true);
       
       await for (final entity in stream.handleError((e){})) {
         if (entity is File) {
           processed++;
           if (processed % 5 == 0) yield ScanStatus(entity.path, processed, count);
           await inspectFile(entity);
         }
       }
    }
  }
}

class ScanStatus {
  final String currentFile;
  final int processedCount;
  final int totalEstimate;
  
  ScanStatus(this.currentFile, this.processedCount, this.totalEstimate);
}