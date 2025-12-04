import 'package:flutter/material.dart';
import 'package:lucide_icons/lucide_icons.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:x2y_av_ultimate/ui/theme_x2y.dart';
import 'package:x2y_av_ultimate/ui/views/scanner_pane.dart';
import 'package:x2y_av_ultimate/ui/views/network_pane.dart';
import 'package:x2y_av_ultimate/ui/views/persistence_pane.dart';
import 'package:x2y_av_ultimate/ui/views/quarantine_pane.dart';
import 'package:x2y_av_ultimate/ui/views/settings_pane.dart';

class MainLayout extends StatefulWidget {
  const MainLayout({super.key});

  @override
  State<MainLayout> createState() => _MainLayoutState();
}

class _MainLayoutState extends State<MainLayout> {
  int _selectedIndex = 0;
  bool _realTimeActive = true;

  late List<Widget> _views;

  @override
  void initState() {
    super.initState();
    _updateViews();
  }

  void _updateViews() {
    _views = [
      const ScannerPane(),
      const NetworkPane(),
      const PersistencePane(),
      const QuarantinePane(),
      SettingsPane(
        shieldActive: _realTimeActive, 
        onToggleShield: (v) {
          setState(() {
            _realTimeActive = v;
            _updateViews(); // Refresh Settings UI state
          });
        }
      ),
    ];
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Column(
        children: [
          // PERSISTENT BANNER
          if (_realTimeActive)
            Container(
              width: double.infinity,
              height: 24,
              color: X2yColors.secure,
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: const [
                  Icon(LucideIcons.shieldCheck, size: 14, color: Colors.black),
                  SizedBox(width: 8),
                  Text("REAL-TIME PROTECTION ACTIVE | MONITORING BACKGROUND PROCESSES", 
                    style: TextStyle(color: Colors.black, fontSize: 10, fontWeight: FontWeight.bold, letterSpacing: 1)
                  ),
                ],
              ),
            ).animate().slideY(begin: -1, end: 0),

          Expanded(
            child: Row(
              children: [
                // SIDEBAR
                Container(
                  width: 240,
                  color: X2yColors.sidebar,
                  child: Column(
                    children: [
                      _buildBrandHeader(),
                      const Divider(color: X2yColors.background),
                      _navItem(0, "Integrity Scan", LucideIcons.scanLine),
                      _navItem(1, "Network Monitor", LucideIcons.activity),
                      _navItem(2, "Persistence Audit", LucideIcons.hardDrive),
                      _navItem(3, "Quarantine Vault", LucideIcons.skull),
                      const Spacer(),
                      const Divider(color: X2yColors.background),
                      _navItem(4, "Settings", LucideIcons.settings),
                      _buildFooter(),
                    ],
                  ),
                ),
                
                // MAIN CONTENT
                Expanded(
                  flex: 3,
                  child: Container(
                    color: X2yColors.background,
                    padding: const EdgeInsets.all(24),
                    child: _views[_selectedIndex],
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBrandHeader() {
    return Padding(
      padding: const EdgeInsets.all(24.0),
      child: Row(
        children: [
          const Icon(LucideIcons.shieldCheck, color: X2yColors.primary, size: 28),
          const SizedBox(width: 12),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: const [
              Text("x2y AV", style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18)),
              Text("ULTIMATE", style: TextStyle(fontSize: 10, color: X2yColors.primary, letterSpacing: 2)),
            ],
          ),
        ],
      ),
    );
  }

  Widget _navItem(int index, String label, IconData icon) {
    bool selected = _selectedIndex == index;
    return ListTile(
      leading: Icon(icon, color: selected ? X2yColors.primary : X2yColors.textDim),
      title: Text(label, style: TextStyle(color: selected ? X2yColors.textMain : X2yColors.textDim)),
      selected: selected,
      selectedTileColor: X2yColors.background.withOpacity(0.5),
      onTap: () => setState(() => _selectedIndex = index),
    );
  }

  Widget _buildFooter() {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Text("Developed by x2y devs tools\nv5.0.0", 
        style: const TextStyle(fontSize: 10, color: X2yColors.textDim),
        textAlign: TextAlign.center,
      ),
    );
  }
}