import 'dart:async';
import 'dart:convert';
import 'dart:io';

class NetConnection {
  final String proto;
  final String local;
  final String remote;
  final String state;
  final String pid;
  final bool isSuspicious; // C2 Logic

  NetConnection(this.proto, this.local, this.remote, this.state, this.pid, this.isSuspicious);
}

class NetworkTracker {
  Future<List<NetConnection>> scanConnections() async {
    final result = await Process.run('netstat', ['-ano']);
    final lines = LineSplitter.split(result.stdout.toString()).toList();
    
    List<NetConnection> connections = [];
    
    for (var line in lines) {
      final parts = line.trim().split(RegExp(r'\s+'));
      if (parts.length >= 5 && (parts[0] == 'TCP' || parts[0] == 'UDP')) {
        String remote = parts[2];
        // Basic Threat Intel: Flag non-standard ports or known suspicious IPs (Mock logic for IPs)
        bool suspicious = remote.endsWith(":4444") || remote.endsWith(":6667") || !remote.startsWith("0.0.0.0"); 
        
        connections.add(NetConnection(
          parts[0], 
          parts[1], 
          remote, 
          parts.length > 3 ? parts[3] : 'UNKNOWN', 
          parts.last,
          suspicious
        ));
      }
    }
    return connections;
  }
}