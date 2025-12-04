import 'dart:io';
import 'package:flutter/material.dart';
import 'package:system_tray/system_tray.dart';
import 'package:window_manager/window_manager.dart';
import 'package:x2y_av_ultimate/core/notification_manager.dart';

class X2yTray {
  static final X2yTray instance = X2yTray._init();
  X2yTray._init();

  final SystemTray _systemTray = SystemTray();
  final AppWindow _appWindow = AppWindow();

  Future<void> init() async {
    // UPDATED: Pointing to your specific asset
    String iconPath = 'assets/x2y_icon.ico';
    
    await _systemTray.initSystemTray(
      title: "x2y AV Ultimate",
      iconPath: iconPath, 
      toolTip: "x2y AV: Real-Time Protection Active",
    );

    final Menu menu = Menu();
    await menu.buildFrom([
      MenuItemLabel(label: 'Open Dashboard', onClicked: (menuItem) => _appWindow.show()),
      MenuSeparator(),
      MenuItemLabel(label: 'Exit x2y AV', onClicked: (menuItem) async {
        await windowManager.destroy();
      }),
    ]);

    await _systemTray.setContextMenu(menu);

    _systemTray.registerSystemTrayEventHandler((eventName) {
      if (eventName == kSystemTrayEventClick) {
        Platform.isWindows ? _appWindow.show() : _systemTray.popUpContextMenu();
      } else if (eventName == kSystemTrayEventRightClick) {
        Platform.isWindows ? _systemTray.popUpContextMenu() : _appWindow.show();
      }
    });
  }
}