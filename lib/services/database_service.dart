import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:path/path.dart';
import 'package:path_provider/path_provider.dart';
import 'package:x2y_av_ultimate/core/notification_manager.dart';

class DatabaseService {
  static final DatabaseService instance = DatabaseService._init();
  static Database? _database;
  
  // --- PRODUCTION THREAT FEEDS (Free/Open Source) ---
  // 1. MalwareBazaar: Recent confirmed malware (Ransomware, Trojans)
  static const String _feedMalwareBazaar = "https://bazaar.abuse.ch/export/txt/sha256/recent/";
  // 2. Feodo Tracker: Botnet C2 Binaries
  static const String _feedFeodo = "https://feodotracker.abuse.ch/downloads/malware_hashes.txt";
  // 3. SSL Blacklist: Malicious JA3 fingerprints (Advanced)
  static const String _feedSSL = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv";

  // --- DIAGNOSTIC SIGNATURES (Industry Standard) ---
  // Every real AV must detect EICAR to prove the engine is active.
  static const Map<String, String> _standardSignatures = {
    '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f': 'Standard-Diagnostic-EICAR',
    '44d88612fea8a8f36de82e1278abb02f': 'Standard-Diagnostic-EICAR-MD5', 
  };

  DatabaseService._init();

  Future<Database> get database async {
    if (_database != null) return _database!;
    _database = await _initDB('x2y_ultimate_production_v4.db');
    return _database!;
  }

  Future<Database> _initDB(String filePath) async {
    sqfliteFfiInit();
    databaseFactory = databaseFactoryFfi;
    final dbPath = await getApplicationSupportDirectory();
    final path = join(dbPath.path, filePath);

    return await openDatabase(
      path, 
      version: 1, 
      onCreate: (db, version) async {
        // Threats Table: Optimized for 100k+ entries
        await db.execute('CREATE TABLE threats (hash TEXT PRIMARY KEY, type TEXT, source TEXT)');
        await db.execute('CREATE INDEX idx_hash ON threats(hash)');

        // History Table
        await db.execute('''
          CREATE TABLE history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            date INTEGER,
            filesScanned INTEGER,
            threatsFound INTEGER,
            result TEXT
          )
        ''');

        // Seed Standards
        await _seedStandards(db);
      },
    );
  }

  Future<void> _seedStandards(DatabaseExecutor db) async {
    final batch = db.batch();
    _standardSignatures.forEach((hash, name) {
      batch.insert('threats', {'hash': hash, 'type': name, 'source': 'System-Diagnostic'}, 
        conflictAlgorithm: ConflictAlgorithm.replace);
    });
    await batch.commit(noResult: true);
  }

  // --- MULTI-SOURCE AGGREGATOR ---
  Future<void> updateDefinitions() async {
    X2yNotifier.show("Updating Database", "Aggregating global threat feeds...");
    int totalCount = 0;
    
    final db = await instance.database;

    try {
      await db.transaction((txn) async {
        // 1. Wipe old dynamic data (Keep standards)
        await txn.delete('threats', where: "source != 'System-Diagnostic'");

        // 2. Fetch MalwareBazaar (General Malware)
        totalCount += await _ingestFeed(txn, _feedMalwareBazaar, "MalwareBazaar", "General Malware");

        // 3. Fetch Feodo Tracker (Botnets)
        totalCount += await _ingestFeed(txn, _feedFeodo, "Feodo", "Botnet Binary");
      });

      X2yNotifier.show("Intelligence Updated", "Database active with $totalCount real-world signatures.");
    } catch (e) {
      print("Aggregator Error: $e");
      X2yNotifier.show("Update Error", "Failed to aggregate feeds. Check network.");
    }
  }

  Future<int> _ingestFeed(Transaction txn, String url, String sourceName, String defaultType) async {
    try {
      final response = await http.get(Uri.parse(url));
      if (response.statusCode != 200) return 0;

      final lines = LineSplitter.split(response.body);
      int added = 0;

      for (var line in lines) {
        // Skip comments and headers
        if (line.startsWith('#') || line.trim().isEmpty || line.startsWith('first_seen')) continue;

        // Clean parsing
        String hash = "";
        String type = defaultType;

        // Feodo/MalwareBazaar often use CSV or plain lists
        if (line.contains(',')) {
          // Attempt CSV parsing (hash is usually index 1 or 2 depending on feed)
          var parts = line.split(',');
          // Simple heuristic: look for length 64 (SHA256)
          var potentialHash = parts.firstWhere((p) => p.trim().length == 64, orElse: () => "");
          if (potentialHash.isNotEmpty) hash = potentialHash;
        } else {
          // Plain text list
          if (line.trim().length == 64) hash = line.trim();
        }

        if (hash.isNotEmpty) {
          await txn.insert('threats', {
            'hash': hash,
            'type': type,
            'source': sourceName
          }, conflictAlgorithm: ConflictAlgorithm.ignore); // Ignore duplicates
          added++;
        }
      }
      return added;
    } catch (e) {
      print("Error reading $sourceName: $e");
      return 0;
    }
  }

  // --- ENGINE METHODS ---
  Future<bool> isThreat(String hash) async {
    final db = await instance.database;
    final res = await db.query('threats', where: 'hash = ?', whereArgs: [hash]);
    return res.isNotEmpty;
  }

  Future<int> getSignatureCount() async {
    final db = await instance.database;
    final result = await db.rawQuery('SELECT COUNT(*) FROM threats');
    if (result.isNotEmpty && result.first.values.isNotEmpty) {
      return (result.first.values.first as int?) ?? 0;
    }
    return 0;
  }

  Future<void> logScan(String type, int files, int threats) async {
    final db = await instance.database;
    await db.insert('history', {
      'type': type,
      'date': DateTime.now().millisecondsSinceEpoch,
      'filesScanned': files,
      'threatsFound': threats,
      'result': threats > 0 ? "THREATS DETECTED" : "CLEAN"
    });
  }

  Future<List<Map<String, dynamic>>> getHistory() async {
    final db = await instance.database;
    return await db.query('history', orderBy: 'date DESC');
  }
}