import 'package:flutter/material.dart';
import 'package:lucide_icons/lucide_icons.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:x2y_av_ultimate/ui/theme_x2y.dart';
import 'package:x2y_av_ultimate/engine/av_core.dart';
import 'package:x2y_av_ultimate/core/startup_manager.dart';
import 'package:x2y_av_ultimate/services/database_service.dart';

class SettingsPane extends StatefulWidget {
  final Function(bool) onToggleShield;
  final bool shieldActive;

  const SettingsPane({super.key, required this.onToggleShield, required this.shieldActive});

  @override
  State<SettingsPane> createState() => _SettingsPaneState();
}

class _SettingsPaneState extends State<SettingsPane> {
  final TextEditingController _excludeController = TextEditingController();
  
  bool _scheduleEnabled = false;
  bool _startupEnabled = false;
  TimeOfDay _scanTime = const TimeOfDay(hour: 12, minute: 0);

  @override
  void initState() {
    super.initState();
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    bool startup = await StartupManager.isStartupEnabled();
    
    setState(() {
      _scheduleEnabled = prefs.getBool('schedule_enabled') ?? false;
      _startupEnabled = startup;
      int h = prefs.getInt('schedule_hour') ?? 12;
      int m = prefs.getInt('schedule_minute') ?? 0;
      _scanTime = TimeOfDay(hour: h, minute: m);
    });
  }

  Future<void> _toggleStartup(bool val) async {
    await StartupManager.setStartup(val);
    setState(() => _startupEnabled = val);
  }

  Future<void> _saveSchedule(bool enabled, TimeOfDay time) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('schedule_enabled', enabled);
    await prefs.setInt('schedule_hour', time.hour);
    await prefs.setInt('schedule_minute', time.minute);
    
    setState(() {
      _scheduleEnabled = enabled;
      _scanTime = time;
    });
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        const Text("Settings & Policy", style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
        const SizedBox(height: 20),

        // 0. THREAT INTELLIGENCE (DATABASE)
        const Text("THREAT INTELLIGENCE", style: TextStyle(color: X2yColors.primary, fontSize: 11, fontWeight: FontWeight.bold)),
        ListTile(
          leading: const Icon(LucideIcons.database, color: X2yColors.textMain),
          title: const Text("Update Virus Definitions"),
          subtitle: FutureBuilder<int>(
            future: DatabaseService.instance.getSignatureCount(),
            builder: (c, s) => Text(s.hasData ? "${s.data} signatures loaded" : "Checking database..."),
          ),
          trailing: IconButton(
            icon: const Icon(LucideIcons.refreshCw, color: X2yColors.secure),
            onPressed: () async {
              await DatabaseService.instance.updateDefinitions();
              // Trigger rebuild to show new count
              setState(() {}); 
            },
          ),
        ),
        
        const Divider(color: X2yColors.sidebar),
        const SizedBox(height: 10),

        // 1. PROTECTION
        const Text("REAL-TIME PROTECTION", style: TextStyle(color: X2yColors.primary, fontSize: 11, fontWeight: FontWeight.bold)),
        SwitchListTile(
          title: const Text("Background Shield"),
          subtitle: const Text("Monitor downloads and execution events."),
          value: widget.shieldActive,
          activeColor: X2yColors.secure,
          onChanged: widget.onToggleShield,
        ),
        
        SwitchListTile(
          title: const Text("Run on Startup"),
          subtitle: const Text("Start protection automatically when Windows boots."),
          value: _startupEnabled,
          activeColor: X2yColors.secure,
          onChanged: _toggleStartup,
        ),

        const Divider(color: X2yColors.sidebar),
        const SizedBox(height: 10),

        // 2. EXCLUSIONS
        const Text("EXCLUSION ZONES", style: TextStyle(color: X2yColors.primary, fontSize: 11, fontWeight: FontWeight.bold)),
        Row(children: [
          Expanded(child: TextField(controller: _excludeController, decoration: const InputDecoration(hintText: "Add path...", isDense: true))),
          IconButton(icon: const Icon(LucideIcons.plus), onPressed: () {
            if(_excludeController.text.isNotEmpty) setState(() => AVCore.exclusionPaths.add(_excludeController.text));
          })
        ]),
        Column(
          children: AVCore.exclusionPaths.map((e) => ListTile(
            dense: true, 
            title: Text(e), 
            trailing: IconButton(icon: const Icon(Icons.close, size: 14), onPressed: () => setState(() => AVCore.exclusionPaths.remove(e)))
          )).toList(),
        ),

        const Divider(color: X2yColors.sidebar),
        const SizedBox(height: 10),

        // 3. SCHEDULER
        const Text("AUTOMATED TASKS", style: TextStyle(color: X2yColors.primary, fontSize: 11, fontWeight: FontWeight.bold)),
        ListTile(
          title: const Text("Daily Quick Scan"),
          subtitle: Text(_scheduleEnabled ? "Runs daily at ${_scanTime.format(context)}" : "Disabled"),
          trailing: Switch(
            value: _scheduleEnabled,
            activeColor: X2yColors.primary,
            onChanged: (v) => _saveSchedule(v, _scanTime),
          ),
          onTap: () async {
            final t = await showTimePicker(context: context, initialTime: _scanTime);
            if(t != null) _saveSchedule(_scheduleEnabled, t);
          },
        ),

        const Divider(color: X2yColors.sidebar),
        const SizedBox(height: 10),
        
        // 4. SUPPORT
        ListTile(
          leading: const Icon(LucideIcons.mail, color: X2yColors.textDim),
          title: const Text("Contact Support"),
          subtitle: const Text("support@x2ydevs.xyz"),
          onTap: () async {
            final uri = Uri.parse("mailto:support@x2ydevs.xyz");
            if (await canLaunchUrl(uri)) launchUrl(uri);
          },
        ),
      ],
    );
  }
}