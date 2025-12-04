import 'dart:io';
import 'dart:async';
import 'package:path_provider/path_provider.dart';
import 'package:x2y_av_ultimate/engine/av_core.dart';

class ShieldService {
  final AVCore _core;
  List<StreamSubscription> _watchers = [];
  bool isActive = false;

  ShieldService(this._core);

  Future<void> engageShields() async {
    if (isActive) return;
    isActive = true;

    // We monitor high-risk entry points
    List<Directory> watchTargets = [];
    
    // 1. Downloads
    final downloads = await getDownloadsDirectory();
    if (downloads != null) watchTargets.add(downloads);

    // 2. Desktop & Documents (Using Environment Vars for Windows)
    final userProfile = Platform.environment['USERPROFILE'];
    if (userProfile != null) {
      watchTargets.add(Directory('$userProfile\\Desktop'));
      watchTargets.add(Directory('$userProfile\\Documents'));
      watchTargets.add(Directory('$userProfile\\AppData\\Local\\Temp')); // Malware staging area
    }

    for (var dir in watchTargets) {
      if (dir.existsSync()) {
        print("Monitoring: ${dir.path}");
        var stream = dir.watch(events: FileSystemEvent.all, recursive: false);
        var sub = stream.listen((event) async {
           if (event is FileSystemCreateEvent || event is FileSystemModifyEvent) {
             if (FileSystemEntity.isFileSync(event.path)) {
               // Rate limit slightly to let file write finish
               await Future.delayed(const Duration(milliseconds: 500));
               _core.inspectFile(File(event.path));
             }
           }
        });
        _watchers.add(sub);
      }
    }
  }

  void disengageShields() {
    for (var sub in _watchers) sub.cancel();
    _watchers.clear();
    isActive = false;
  }
}