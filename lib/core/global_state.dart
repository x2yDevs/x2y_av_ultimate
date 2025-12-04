import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:path/path.dart' as p;
import 'package:x2y_av_ultimate/engine/av_core.dart';
import 'package:x2y_av_ultimate/services/database_service.dart';
import 'package:x2y_av_ultimate/core/notification_manager.dart';

class GlobalState extends ChangeNotifier {
  static final GlobalState instance = GlobalState._init();
  GlobalState._init();

  final AVCore _engine = AVCore();
  
  // --- SCAN UI STATE ---
  bool isScanning = false;
  String scanType = "Idle";
  String currentFile = "";
  int filesProcessed = 0;
  int totalEstimate = 1;
  String timeRemaining = "--:--";
  double progress = 0.0;
  DateTime? _startTime;

  // --- BACKGROUND SERVICES STATE ---
  Timer? _schedulerTimer;
  final List<StreamSubscription> _fileWatchers = [];
  bool isShieldActive = false;

  // ------------------------------------------------------------------------
  // 1. REAL-TIME SHIELD LOGIC (Directory Watcher)
  // ------------------------------------------------------------------------
  Future<void> toggleShield(bool enable) async {
    isShieldActive = enable;
    
    // Save preference
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('shield_active', enable);

    if (enable) {
      _startWatchers();
      X2yNotifier.show("Shield Active", "Real-Time file monitoring engaged.");
    } else {
      _stopWatchers();
      X2yNotifier.show("Shield Disabled", "Background monitoring stopped.");
    }
    notifyListeners();
  }

  void _startWatchers() {
    // Monitor High-Risk Directories
    List<String> paths = [];
    
    String? userProfile = Platform.environment['USERPROFILE'];
    if (userProfile != null) {
      paths.add(p.join(userProfile, 'Downloads'));
      paths.add(p.join(userProfile, 'Desktop'));
      paths.add(p.join(userProfile, 'Documents'));
    }

    for (var path in paths) {
      final dir = Directory(path);
      if (dir.existsSync()) {
        try {
          // Listen for File Creation and Modification events
          final stream = dir.watch(events: FileSystemEvent.all, recursive: false);
          final sub = stream.listen((event) async {
            if (event is FileSystemCreateEvent || event is FileSystemModifyEvent) {
               if (FileSystemEntity.isFileSync(event.path)) {
                 // Small delay to let file write release lock
                 await Future.delayed(const Duration(milliseconds: 500));
                 _backgroundInspect(File(event.path));
               }
            }
          });
          _fileWatchers.add(sub);
        } catch (e) {
          print("Failed to watch $path: $e");
        }
      }
    }
  }

  void _stopWatchers() {
    for (var sub in _fileWatchers) sub.cancel();
    _fileWatchers.clear();
  }

  Future<void> _backgroundInspect(File file) async {
    // Only scan if not currently excluded
    if (AVCore.exclusionPaths.any((ex) => file.path.startsWith(ex))) return;

    // Silent Scan (Does not update UI progress bar, runs in background)
    bool safe = await _engine.inspectFile(file);
    if (!safe) {
      X2yNotifier.show("Threat Blocked", "Real-Time Shield stopped ${p.basename(file.path)}", isCritical: true);
      DatabaseService.instance.logScan("Real-Time", 1, 1);
    }
  }

  // ------------------------------------------------------------------------
  // 2. SCANNING ENGINE LOGIC
  // ------------------------------------------------------------------------
  Future<void> startScan(String type, {String? customPath}) async {
    if (isScanning) return; 

    isScanning = true;
    scanType = type;
    filesProcessed = 0;
    progress = 0.0;
    _startTime = DateTime.now();
    notifyListeners();

    Stream<ScanStatus> stream;
    if (type == "Quick") {
      stream = _engine.runQuickScan();
    } else if (type == "Full") {
      stream = _engine.runFullScan();
    } else if (type == "Custom" && customPath != null) {
      stream = _engine.runCustomPathScan(customPath);
    } else {
       isScanning = false;
       notifyListeners();
       return;
    }

    int threats = 0;
    // ... (Scan loop logic remains same as previous step) ...
    await for (final status in stream) {
      currentFile = status.currentFile;
      filesProcessed = status.processedCount;
      totalEstimate = status.totalEstimate;
      progress = (filesProcessed / totalEstimate).clamp(0.0, 1.0);
      _updateTime();
      notifyListeners();
      await Future.delayed(Duration.zero);
    }

    await DatabaseService.instance.logScan(type, filesProcessed, threats);

    isScanning = false;
    currentFile = "Scan Complete";
    progress = 1.0;
    timeRemaining = "Finished";
    notifyListeners();
    X2yNotifier.show("Scan Finished", "$type Scan complete. $filesProcessed items analyzed.");
  }

  void _updateTime() {
    final elapsed = DateTime.now().difference(_startTime!);
    if (filesProcessed > 0 && elapsed.inSeconds > 1) {
       double rate = filesProcessed / elapsed.inMilliseconds; 
       double remaining = (totalEstimate - filesProcessed) / rate;
       if (remaining < 60000) {
         timeRemaining = "${(remaining/1000).toStringAsFixed(0)}s";
       } else {
         timeRemaining = "${(remaining/60000).toStringAsFixed(0)}m";
       }
    }
  }

  // ------------------------------------------------------------------------
  // 3. SCHEDULER & INIT
  // ------------------------------------------------------------------------
  Future<void> initSystem() async {
    final prefs = await SharedPreferences.getInstance();
    
    // 1. Restore Shield State
    bool shieldOn = prefs.getBool('shield_active') ?? true;
    if (shieldOn) toggleShield(true);

    // 2. Start Scheduler (Check every 60s)
    _schedulerTimer?.cancel();
    _schedulerTimer = Timer.periodic(const Duration(minutes: 1), (timer) async {
      bool enabled = prefs.getBool('schedule_enabled') ?? false;
      if (!enabled) return;

      int hour = prefs.getInt('schedule_hour') ?? 12;
      int minute = prefs.getInt('schedule_minute') ?? 0;
      int lastRun = prefs.getInt('last_run_day') ?? 0;

      final now = DateTime.now();
      
      // Trigger if times match and we haven't run today
      if (now.hour == hour && now.minute == minute && lastRun != now.day) {
        if (!isScanning) {
          await prefs.setInt('last_run_day', now.day);
          X2yNotifier.show("Scheduled Scan", "Daily System Scan is starting...");
          startScan("Quick"); 
        }
      }
    });
  }
}