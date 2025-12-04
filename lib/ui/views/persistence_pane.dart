import 'package:flutter/material.dart';
import 'package:lucide_icons/lucide_icons.dart';
import 'package:x2y_av_ultimate/core/persistence_auditor.dart';
import 'package:x2y_av_ultimate/core/notification_manager.dart';
import 'package:x2y_av_ultimate/ui/theme_x2y.dart';

class PersistencePane extends StatefulWidget {
  const PersistencePane({super.key});

  @override
  State<PersistencePane> createState() => _PersistencePaneState();
}

class _PersistencePaneState extends State<PersistencePane> {
  final PersistenceAuditor _auditor = PersistenceAuditor();
  List<PersistenceItem> _items = [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _scan();
  }

  Future<void> _scan() async {
    // FIXED: Changed from scanRegistry() to runAudit()
    final list = await _auditor.runAudit();
    if(mounted) {
      setState(() { _items = list; _loading = false; });
      X2yNotifier.show("Audit Complete", "Scanned ${list.length} startup items.");
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text("Persistence Auditor", style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
        const Text("Registry Run Keys & Startup Folder", style: TextStyle(color: X2yColors.textDim)),
        const SizedBox(height: 20),
        if (_loading) 
          const LinearProgressIndicator(color: X2yColors.primary, backgroundColor: X2yColors.sidebar),
        
        Expanded(
          child: ListView.builder(
            itemCount: _items.length,
            itemBuilder: (context, index) {
              final item = _items[index];
              return Card(
                color: X2yColors.sidebar,
                child: ListTile(
                  leading: const Icon(LucideIcons.hardDrive, color: X2yColors.warning),
                  title: Text(item.name, overflow: TextOverflow.ellipsis),
                  // FIXED: Changed from item.hive to item.type
                  subtitle: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const SizedBox(height: 4),
                      Text("TYPE: ${item.type}", style: const TextStyle(fontSize: 10, color: X2yColors.primary, fontWeight: FontWeight.bold)),
                      Text("PATH: ${item.path}", style: const TextStyle(fontSize: 10, fontFamily: 'Consolas', color: X2yColors.textDim)),
                    ],
                  ),
                ),
              );
            },
          ),
        )
      ],
    );
  }
}