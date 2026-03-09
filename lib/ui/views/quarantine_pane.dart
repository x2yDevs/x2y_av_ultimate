import 'dart:io';
import 'package:flutter/material.dart';
import 'package:lucide_icons/lucide_icons.dart';
import 'package:x2y_av_ultimate/core/quarantine_manager.dart';
import 'package:x2y_av_ultimate/ui/theme_x2y.dart';

class QuarantinePane extends StatefulWidget {
  const QuarantinePane({super.key});

  @override
  State<QuarantinePane> createState() => _QuarantinePaneState();
}

class _QuarantinePaneState extends State<QuarantinePane> {
  final QuarantineManager _manager = QuarantineManager();
  List<File> _files = [];

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    final list = await _manager.getQuarantinedFiles();
    if(mounted) setState(() => _files = list);
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text("Quarantine Vault", style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
        const Text("Isolated Threats (.x2y_quarantine)", style: TextStyle(color: X2yColors.textDim)),
        const SizedBox(height: 20),
        
        Expanded(
          child: _files.isEmpty 
          ? Center(child: Text("Vault Empty", style: TextStyle(color: X2yColors.textDim)))
          : GridView.builder(
              gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                crossAxisCount: 4, 
                childAspectRatio: 1.0,
                crossAxisSpacing: 10,
                mainAxisSpacing: 10
              ),
              itemCount: _files.length,
              itemBuilder: (context, index) {
                final file = _files[index];
                final name = file.path.split(Platform.pathSeparator).last;
                return Container(
                  decoration: BoxDecoration(
                    color: X2yColors.sidebar,
                    border: Border.all(color: X2yColors.threat),
                    borderRadius: BorderRadius.circular(8)
                  ),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      const Icon(LucideIcons.skull, color: X2yColors.threat, size: 32),
                      const SizedBox(height: 8),
                      Padding(
                        padding: const EdgeInsets.all(8.0),
                        child: Text(name, style: const TextStyle(fontSize: 10), textAlign: TextAlign.center, maxLines: 2),
                      ),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          IconButton(
                            icon: const Icon(LucideIcons.undo, size: 16),
                            onPressed: () async {
                              await _manager.restoreFile(file);
                              _refresh();
                            },
                          ),
                          IconButton(
                            icon: const Icon(LucideIcons.trash2, size: 16, color: X2yColors.threat),
                            onPressed: () async {
                              await _manager.deletePermanently(file);
                              _refresh();
                            },
                          ),
                        ],
                      )
                    ],
                  ),
                );
              },
            ),
        )
      ],
    );
  }
}