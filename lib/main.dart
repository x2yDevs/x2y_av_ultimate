import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:x2y_av_ultimate/core/notification_manager.dart';
import 'package:x2y_av_ultimate/core/global_state.dart';
import 'package:x2y_av_ultimate/core/tray_manager.dart';
import 'package:x2y_av_ultimate/ui/main_layout.dart';
import 'package:x2y_av_ultimate/ui/theme_x2y.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  sqfliteFfiInit(); 
  
  await X2yNotifier.init();
  await GlobalState.instance.initSystem();
  await X2yTray.instance.init();

  await windowManager.ensureInitialized();
  WindowOptions windowOptions = const WindowOptions(
    size: Size(1280, 800),
    center: true,
    backgroundColor: X2yColors.background,
    skipTaskbar: false,
    titleBarStyle: TitleBarStyle.normal,
    title: "x2y AV Ultimate",
  );
  
  windowManager.waitUntilReadyToShow(windowOptions, () async {
    await windowManager.show();
    await windowManager.focus();
    
    // --- FORCE TASKBAR ICON UPDATE ---
    await windowManager.setIcon('assets/x2y_icon.ico'); 
    
    // Prevent closing (Minimize to tray logic)
    await windowManager.setPreventClose(true); 
  });

  runApp(const X2yApp());
}

class X2yApp extends StatefulWidget {
  const X2yApp({super.key});

  @override
  State<X2yApp> createState() => _X2yAppState();
}

class _X2yAppState extends State<X2yApp> with WindowListener {
  @override
  void initState() {
    super.initState();
    windowManager.addListener(this);
  }

  @override
  void dispose() {
    windowManager.removeListener(this);
    super.dispose();
  }

  @override
  void onWindowClose() async {
    bool isPreventClose = await windowManager.isPreventClose();
    if (isPreventClose) {
      await windowManager.hide();
      X2yNotifier.show("x2y AV is running", "Protection is active in the background.");
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'x2y AV Ultimate',
      debugShowCheckedModeBanner: false,
      theme: X2yTheme.dark,
      home: const MainLayout(),
    );
  }
}