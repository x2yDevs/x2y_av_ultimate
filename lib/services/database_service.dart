import 'dart:async';
import 'dart:io';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:path/path.dart';
import 'package:path_provider/path_provider.dart';

class DatabaseService {
  static final DatabaseService instance = DatabaseService._init();
  static Database? _database;

  DatabaseService._init();

  Future<Database> get database async {
    if (_database != null) return _database!;
    _database = await _initDB('x2y_ultimate_v6.db');
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
        // 1. Threats Table (Hashes)
        await db.execute('''
          CREATE TABLE threats (
            hash TEXT PRIMARY KEY,
            source TEXT,
            timestamp INTEGER
          )
        ''');
        await db.execute('CREATE INDEX idx_hash ON threats(hash)');

        // 2. History Table (Scan Logs)
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
      },
    );
  }

  // --- HISTORY METHODS ---
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

  Future<void> clearHistory() async {
    final db = await instance.database;
    await db.delete('history');
  }

  // --- THREAT METHODS ---
  Future<bool> isThreat(String hash) async {
    final db = await instance.database;
    final res = await db.query('threats', where: 'hash = ?', whereArgs: [hash]);
    return res.isNotEmpty;
  }
}