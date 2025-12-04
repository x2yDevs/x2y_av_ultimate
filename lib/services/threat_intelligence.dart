import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:path/path.dart';
import 'package:path_provider/path_provider.dart';

class ThreatIntelligence {
  static final ThreatIntelligence instance = ThreatIntelligence._init();
  static Database? _database;
  
  // REAL Threat Feed URLs
  // MalwareBazaar Recent SHA256 (Txt) - Updated hourly
  static const String _malwareBazaarFeed = "https://bazaar.abuse.ch/export/txt/sha256/recent/";
  
  final StreamController<String> _statusController = StreamController.broadcast();
  Stream<String> get statusStream => _statusController.stream;

  ThreatIntelligence._init();

  Future<Database> get database async {
    if (_database != null) return _database!;
    _database = await _initDB('x2y_ultimate_defs.db');
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
        // Optimized table for fast hash lookups
        await db.execute('''
          CREATE TABLE threats (
            hash TEXT PRIMARY KEY,
            source TEXT,
            timestamp INTEGER
          )
        ''');
        await db.execute('CREATE INDEX idx_hash ON threats(hash)');
      },
    );
  }

  // 1. UPDATE DEFINITIONS (Live Internet Fetch)
  Future<void> updateDefinitions() async {
    _statusController.add("Connecting to MalwareBazaar (abuse.ch)...");
    
    try {
      final response = await http.get(Uri.parse(_malwareBazaarFeed));
      if (response.statusCode == 200) {
        _statusController.add("Download Complete. Parsing Threat Data...");
        await _processBatchImport(response.body);
      } else {
        _statusController.add("Error: Failed to fetch feed (${response.statusCode})");
      }
    } catch (e) {
      _statusController.add("Connection Error: $e");
    }
  }

  // 2. BULK IMPORT LOGIC (Transactions for speed)
  Future<void> _processBatchImport(String rawData) async {
    final db = await instance.database;
    final lines = LineSplitter.split(rawData).toList();
    
    int count = 0;
    await db.transaction((txn) async {
      for (var line in lines) {
        // Skip comments in the feed
        if (line.startsWith('#') || line.trim().isEmpty) continue;
        
        // MalwareBazaar format: SHA256
        String hash = line.trim();
        if (hash.length == 64) {
          await txn.insert('threats', {
            'hash': hash,
            'source': 'MalwareBazaar',
            'timestamp': DateTime.now().millisecondsSinceEpoch
          }, conflictAlgorithm: ConflictAlgorithm.replace);
          count++;
        }
      }
    });
    
    _statusController.add("Database Updated: $count new signatures added.");
  }

  // 3. CHECK HASH
  Future<bool> isThreat(String hash) async {
    final db = await instance.database;
    final result = await db.query(
      'threats',
      columns: ['hash'],
      where: 'hash = ?',
      whereArgs: [hash],
      limit: 1,
    );
    return result.isNotEmpty;
  }
  
  // 4. API CLOUD LOOKUP (Fallback if not in local DB)
  // Uses MalwareBazaar API for individual lookup
  Future<bool> checkCloudAPI(String hash) async {
    try {
      // Create POST request form data
      var response = await http.post(
        Uri.parse('https://mb-api.abuse.ch/api/v1/'),
        body: {'query': 'get_info', 'hash': hash}
      );

      if (response.statusCode == 200) {
        var json = jsonDecode(response.body);
        return json['query_status'] == 'ok'; // 'ok' means malware found
      }
    } catch (e) {
      // Fail safely on network error
    }
    return false;
  }

  Future<int> getThreatCount() async {
    final db = await instance.database;
    final result = await db.rawQuery('SELECT COUNT(*) FROM threats');
    if (result.isNotEmpty && result.first.values.isNotEmpty) {
      return (result.first.values.first as int?) ?? 0;
    }
    return 0;
  }
}