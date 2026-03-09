import 'dart:async';
import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:x2y_av_ultimate/core/network_tracker.dart';
import 'package:x2y_av_ultimate/ui/theme_x2y.dart';

class NetworkPane extends StatefulWidget {
  const NetworkPane({super.key});

  @override
  State<NetworkPane> createState() => _NetworkPaneState();
}

class _NetworkPaneState extends State<NetworkPane> {
  final NetworkTracker _tracker = NetworkTracker();
  List<NetConnection> _connections = [];
  List<FlSpot> _spots = [];
  double _timeCounter = 0;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(const Duration(seconds: 2), (timer) => _refresh());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _refresh() async {
    final list = await _tracker.scanConnections();
    if (mounted) {
      setState(() {
        _connections = list;
        _timeCounter++;
        if (_spots.length > 20) _spots.removeAt(0);
        _spots.add(FlSpot(_timeCounter, list.length.toDouble()));
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text("Network Activity Monitor", style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
        const Text("Real-time Process Mapping & Traffic Flow", style: TextStyle(color: X2yColors.textDim)),
        const SizedBox(height: 20),
        
        // GRAPH
        SizedBox(
          height: 150,
          child: LineChart(
            LineChartData(
              gridData: const FlGridData(show: false),
              titlesData: const FlTitlesData(show: false),
              borderData: FlBorderData(show: true, border: Border.all(color: X2yColors.sidebar)),
              lineBarsData: [
                LineChartBarData(
                  spots: _spots,
                  isCurved: true,
                  color: X2yColors.primary,
                  barWidth: 3,
                  isStrokeCapRound: true,
                  dotData: const FlDotData(show: false),
                  belowBarData: BarAreaData(show: true, color: X2yColors.primary.withOpacity(0.2)),
                ),
              ],
            ),
          ),
        ),
        
        const SizedBox(height: 20),
        
        // TABLE
        Expanded(
          child: Container(
            decoration: BoxDecoration(border: Border.all(color: X2yColors.sidebar), borderRadius: BorderRadius.circular(8)),
            child: ListView.separated(
              itemCount: _connections.length,
              separatorBuilder: (c, i) => const Divider(height: 1, color: X2yColors.sidebar),
              itemBuilder: (context, index) {
                final c = _connections[index];
                return ListTile(
                  dense: true,
                  leading: Icon(Icons.circle, size: 8, color: c.isSuspicious ? X2yColors.warning : X2yColors.secure),
                  title: Text("${c.proto}  ${c.remote}"),
                  subtitle: Text("PID: ${c.pid} | State: ${c.state}"),
                  trailing: c.isSuspicious 
                    ? const Chip(label: Text("SUSPICIOUS"), backgroundColor: X2yColors.warning, labelStyle: TextStyle(color: Colors.black, fontSize: 10))
                    : null,
                );
              },
            ),
          ),
        ),
      ],
    );
  }
}