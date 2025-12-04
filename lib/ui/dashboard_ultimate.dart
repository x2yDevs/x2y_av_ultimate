import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:lucide_icons/lucide_icons.dart';
import 'package:x2y_av_ultimate/engine/av_core.dart';
import 'package:x2y_av_ultimate/engine/shield_service.dart';
import 'package:x2y_av_ultimate/services/threat_intelligence.dart';
import 'package:intl/intl.dart';

class DashboardUltimate extends StatefulWidget {
  const DashboardUltimate({super.key});

  @override
  State<DashboardUltimate> createState() => _DashboardUltimateState();
}

class _DashboardUltimateState extends State<DashboardUltimate> {
  final AVCore _core = AVCore();
  late ShieldService _shield;
  
  List<String> _logs = [];
  bool _shieldActive = false;
  int _dbCount = 0;
  String _intelStatus = "Ready";

  @override
  void initState() {
    super.initState();
    _shield = ShieldService(_core);
    
    // Update DB Count
    _refreshDbStats();

    // Logs
    _core.activityLog.listen((log) {
      if(mounted) setState(() => _logs.insert(0, _fmtLog(log)));
    });

    // Intel Status
    ThreatIntelligence.instance.statusStream.listen((status) {
       if(mounted) {
         setState(() => _intelStatus = status);
         if(status.contains("Updated")) _refreshDbStats();
       }
    });

    // Start Shields Default
    _toggleShield(true);
  }

  String _fmtLog(String msg) {
    final now = DateTime.now();
    return "[${DateFormat('HH:mm:ss').format(now)}] $msg";
  }

  Future<void> _refreshDbStats() async {
    int count = await ThreatIntelligence.instance.getThreatCount();
    setState(() => _dbCount = count);
  }

  Future<void> _updateSignatures() async {
    setState(() => _intelStatus = "Initializing Download...");
    await ThreatIntelligence.instance.updateDefinitions();
  }

  void _toggleShield(bool val) {
    if(val) {
      _shield.engageShields();
      setState(() { _shieldActive = true; _logs.insert(0, _fmtLog("Active Protection Engaged")); });
    } else {
      _shield.disengageShields();
      setState(() { _shieldActive = false; _logs.insert(0, _fmtLog("Active Protection Disengaged")); });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0F1C), // Deep Cyber Blue
      body: Row(
        children: [
          // SIDEBAR
          Container(
            width: 260,
            decoration: const BoxDecoration(
              color: Color(0xFF111827),
              border: Border(right: BorderSide(color: Color(0xFF1F2937)))
            ),
            child: Column(
              children: [
                const SizedBox(height: 30),
                const Icon(LucideIcons.shieldCheck, color: Color(0xFF3B82F6), size: 48),
                const SizedBox(height: 10),
                const Text("x2y AV", style: TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.bold)),
                const Text("ULTIMATE", style: TextStyle(color: Color(0xFF3B82F6), fontSize: 14, letterSpacing: 3)),
                const SizedBox(height: 40),
                _navTile("Dashboard", LucideIcons.layoutDashboard, true),
                _navTile("Threat Intel", LucideIcons.globe, false),
                _navTile("Quarantine", LucideIcons.lock, false),
                const Spacer(),
                Padding(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    children: [
                      const Text("Engine v3.0", style: TextStyle(color: Colors.grey)),
                      const SizedBox(height: 5),
                      Text("Signatures: $_dbCount", style: const TextStyle(color: Colors.grey, fontSize: 12)),
                    ],
                  ),
                )
              ],
            ),
          ),
          
          // MAIN CONTENT
          Expanded(
            child: Padding(
              padding: const EdgeInsets.all(30),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // TOP STATUS BAR
                  Row(
                    children: [
                      Expanded(child: _statusCard("Protection Status", _shieldActive ? "ACTIVE" : "DISABLED", _shieldActive ? Colors.green : Colors.red, LucideIcons.shield)),
                      const SizedBox(width: 15),
                      Expanded(child: _statusCard("Threat Database", "$_dbCount Hashes", Colors.blue, LucideIcons.database)),
                      const SizedBox(width: 15),
                      Expanded(child: _statusCard("Cloud Intel", "MalwareBazaar Connected", Colors.purple, LucideIcons.cloudLightning)),
                    ],
                  ),
                  
                  const SizedBox(height: 30),
                  
                  // MAIN ACTION AREA
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Text("Live Event Monitor", style: TextStyle(color: Colors.white, fontSize: 20)),
                      ElevatedButton.icon(
                        icon: const Icon(LucideIcons.refreshCw),
                        label: const Text("UPDATE SIGNATURES"),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFF1D4ED8),
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 15)
                        ),
                        onPressed: _updateSignatures,
                      )
                    ],
                  ),
                  
                  const SizedBox(height: 10),
                  Text("Intel Status: $_intelStatus", style: TextStyle(color: Colors.grey[400], fontSize: 12)),
                  const SizedBox(height: 10),
                  
                  // LOG TERMINAL
                  Expanded(
                    child: Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: Colors.black,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: const Color(0xFF374151))
                      ),
                      child: ListView.builder(
                        itemCount: _logs.length,
                        itemBuilder: (context, index) {
                          final log = _logs[index];
                          Color color = Colors.greenAccent;
                          if(log.contains("THREAT") || log.contains("ELIMINATED")) color = Colors.redAccent;
                          if(log.contains("Disengaged")) color = Colors.orange;
                          
                          return Padding(
                            padding: const EdgeInsets.symmetric(vertical: 2),
                            child: Text(log, style: TextStyle(color: color, fontFamily: 'Consolas', fontSize: 13)),
                          );
                        },
                      ),
                    ),
                  ),
                  
                  const SizedBox(height: 20),
                  SizedBox(
                    width: double.infinity,
                    height: 50,
                    child: ElevatedButton(
                      style: ElevatedButton.styleFrom(
                        backgroundColor: _shieldActive ? const Color(0xFFDC2626) : const Color(0xFF059669),
                      ),
                      onPressed: () => _toggleShield(!_shieldActive),
                      child: Text(_shieldActive ? "DISENGAGE SYSTEM" : "ENGAGE SYSTEM", style: const TextStyle(fontWeight: FontWeight.bold)),
                    ),
                  )
                ],
              ),
            ),
          )
        ],
      ),
    );
  }

  Widget _navTile(String title, IconData icon, bool active) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 10, vertical: 2),
      decoration: BoxDecoration(
        color: active ? const Color(0xFF1F2937) : null,
        borderRadius: BorderRadius.circular(6)
      ),
      child: ListTile(
        leading: Icon(icon, color: active ? const Color(0xFF3B82F6) : Colors.grey),
        title: Text(title, style: TextStyle(color: active ? Colors.white : Colors.grey)),
        dense: true,
      ),
    );
  }

  Widget _statusCard(String title, String value, Color color, IconData icon) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: const Color(0xFF111827),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: const Color(0xFF1F2937))
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(color: color.withOpacity(0.1), borderRadius: BorderRadius.circular(8)),
            child: Icon(icon, color: color),
          ),
          const SizedBox(width: 15),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title, style: const TextStyle(color: Colors.grey, fontSize: 12)),
              Text(value, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16)),
            ],
          )
        ],
      ),
    );
  }
}