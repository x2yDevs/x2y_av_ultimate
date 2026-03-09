import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:lucide_icons/lucide_icons.dart';
import 'package:file_picker/file_picker.dart';
import 'package:intl/intl.dart';
import 'package:x2y_av_ultimate/core/global_state.dart';
import 'package:x2y_av_ultimate/services/database_service.dart';
import 'package:x2y_av_ultimate/ui/theme_x2y.dart';

class ScannerPane extends StatefulWidget {
  const ScannerPane({super.key});

  @override
  State<ScannerPane> createState() => _ScannerPaneState();
}

class _ScannerPaneState extends State<ScannerPane> with SingleTickerProviderStateMixin {
  late TabController _tabController;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // TABS
        Container(
          height: 40,
          margin: const EdgeInsets.only(bottom: 20),
          child: TabBar(
            controller: _tabController,
            indicatorColor: X2yColors.primary,
            labelColor: X2yColors.primary,
            unselectedLabelColor: Colors.grey,
            tabs: const [
              Tab(text: "New Scan", icon: Icon(LucideIcons.scanLine, size: 16)),
              Tab(text: "Scan History", icon: Icon(LucideIcons.history, size: 16)),
            ],
          ),
        ),
        
        Expanded(
          child: TabBarView(
            controller: _tabController,
            children: const [
              ScanControlView(), // The main scanner interface
              HistoryView(),     // The DB history list
            ],
          ),
        )
      ],
    );
  }
}

class ScanControlView extends StatelessWidget {
  const ScanControlView({super.key});

  Future<void> _pickFile(BuildContext context) async {
    FilePickerResult? result = await FilePicker.platform.pickFiles();
    if (result != null && result.files.single.path != null) {
      GlobalState.instance.startScan("Custom", customPath: result.files.single.path!);
    }
  }

  Future<void> _pickFolder(BuildContext context) async {
    String? selectedDirectory = await FilePicker.platform.getDirectoryPath();
    if (selectedDirectory != null) {
      GlobalState.instance.startScan("Custom", customPath: selectedDirectory);
    }
  }

  @override
  Widget build(BuildContext context) {
    // Listen to GlobalState for updates
    return ListenableBuilder(
      listenable: GlobalState.instance,
      builder: (context, child) {
        final state = GlobalState.instance;
        
        return Column(
          children: [
            // STATUS VISUALIZER
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: state.isScanning 
                    ? [X2yColors.primary.withOpacity(0.2), X2yColors.background] 
                    : [X2yColors.sidebar, X2yColors.background],
                ),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: state.isScanning ? X2yColors.primary : X2yColors.sidebar)
              ),
              child: Column(
                children: [
                   Icon(state.isScanning ? LucideIcons.loader : LucideIcons.shieldCheck, size: 48, color: state.isScanning ? X2yColors.primary : X2yColors.secure)
                     .animate(target: state.isScanning ? 1 : 0).rotate(duration: 1.seconds),
                   const SizedBox(height: 16),
                   Text(state.isScanning ? "Scanning: ${state.scanType}" : "System Protected", style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
                   const SizedBox(height: 10),
                   if (state.isScanning) ...[
                     LinearProgressIndicator(value: state.progress, color: X2yColors.primary, backgroundColor: Colors.black),
                     const SizedBox(height: 8),
                     Row(
                       mainAxisAlignment: MainAxisAlignment.spaceBetween,
                       children: [
                         Text(state.timeRemaining, style: const TextStyle(fontSize: 12, color: Colors.grey)),
                         Text("${(state.progress * 100).toInt()}%", style: const TextStyle(fontSize: 12, color: Colors.white)),
                       ],
                     ),
                     const SizedBox(height: 4),
                     Text(state.currentFile, maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(fontSize: 10, color: Colors.grey))
                   ]
                ],
              ),
            ),
            
            const SizedBox(height: 30),
            
            // ACTION GRID
            Expanded(
              child: GridView.count(
                crossAxisCount: 2,
                childAspectRatio: 2.5,
                crossAxisSpacing: 16,
                mainAxisSpacing: 16,
                children: [
                  _btn("Quick Scan", "System Criticals", LucideIcons.zap, () => state.startScan("Quick")),
                  _btn("Full Scan", "Entire Drive", LucideIcons.hardDrive, () => state.startScan("Full")),
                  _btn("Scan File", "Single Target", LucideIcons.file, () => _pickFile(context)),
                  _btn("Scan Folder", "Custom Directory", LucideIcons.folder, () => _pickFolder(context)),
                ],
              ),
            )
          ],
        );
      },
    );
  }

  Widget _btn(String title, String sub, IconData icon, VoidCallback onTap) {
    bool busy = GlobalState.instance.isScanning;
    return ElevatedButton(
      style: ElevatedButton.styleFrom(
        backgroundColor: X2yColors.sidebar,
        foregroundColor: X2yColors.textMain,
        elevation: 0,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8))
      ),
      onPressed: busy ? null : onTap,
      child: Row(
        children: [
          Icon(icon, color: busy ? Colors.grey : X2yColors.primary),
          const SizedBox(width: 16),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Text(title, style: const TextStyle(fontWeight: FontWeight.bold)),
              Text(sub, style: const TextStyle(fontSize: 10, color: Colors.grey)),
            ],
          )
        ],
      ),
    );
  }
}

class HistoryView extends StatelessWidget {
  const HistoryView({super.key});

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<List<Map<String, dynamic>>>(
      future: DatabaseService.instance.getHistory(),
      builder: (context, snapshot) {
        if (!snapshot.hasData) return const Center(child: CircularProgressIndicator());
        if (snapshot.data!.isEmpty) return const Center(child: Text("No scan history."));
        
        return ListView.separated(
          itemCount: snapshot.data!.length,
          separatorBuilder: (c, i) => const Divider(color: X2yColors.sidebar),
          itemBuilder: (context, index) {
            final log = snapshot.data![index];
            final date = DateTime.fromMillisecondsSinceEpoch(log['date']);
            final threats = log['threatsFound'] as int;
            
            return ListTile(
              leading: Icon(threats > 0 ? LucideIcons.alertTriangle : LucideIcons.checkCircle, 
                color: threats > 0 ? X2yColors.threat : X2yColors.secure),
              title: Text("${log['type']} Scan"),
              subtitle: Text(DateFormat('MMM dd, yyyy - HH:mm').format(date)),
              trailing: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  Text(log['result'], style: TextStyle(color: threats > 0 ? X2yColors.threat : X2yColors.secure, fontWeight: FontWeight.bold, fontSize: 12)),
                  Text("${log['filesScanned']} items", style: const TextStyle(fontSize: 10, color: Colors.grey)),
                ],
              ),
            );
          },
        );
      },
    );
  }
}