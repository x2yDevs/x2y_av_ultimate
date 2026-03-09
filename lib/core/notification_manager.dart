import 'package:local_notifier/local_notifier.dart';

class X2yNotifier {
  static Future<void> init() async {
    await localNotifier.setup(
      appName: 'x2y AV',
      shortcutPolicy: ShortcutPolicy.requireCreate,
    );
  }

  static void show(String title, String body, {bool isCritical = false}) {
    LocalNotification notification = LocalNotification(
      title: title,
      body: body,
      silent: false,
    );
    
    notification.show();
  }
}