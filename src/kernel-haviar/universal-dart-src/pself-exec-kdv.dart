import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

class SectionFingerprint {
  final String sectionName;
  final List<int> hash;

  SectionFingerprint(this.sectionName, this.hash);

  @override
  String toString() => 'Section: $sectionName, Hash: ${base64.encode(hash)}';
}

class KdvVerifier {
  final Map<String, List<int>> _fingerprints = {};

  void loadInitialFingerprints(Map<String, Uint8List> sections) {
    sections.forEach((name, content) {
      final hash = _computeHash(content);
      _fingerprints[name] = hash;
      print('[INIT] Loaded fingerprint for $name');
    });
  }

  bool verify(String name, Uint8List content) {
    final currentHash = _computeHash(content);
    final expectedHash = _fingerprints[name];

    if (expectedHash == null) {
      print('[ERROR] Unknown section: $name');
      return false;
    }

    if (!_listEquals(expectedHash, currentHash)) {
      print('[ALERT] Integrity violation in section: $name');
      return false;
    }

    print('[OK] Section verified: $name');
    return true;
  }

  List<int> _computeHash(Uint8List data) {
    final digest = sha256.convert(data);
    return digest.bytes;
  }

  bool _listEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

Future<Map<String, Uint8List>> loadFilesAsSections(List<String> paths) async {
  final map = <String, Uint8List>{};
  for (var path in paths) {
    final file = File(path);
    if (await file.exists()) {
      final bytes = await file.readAsBytes();
      map[path] = bytes;
    }
  }
  return map;
}

void main(List<String> args) async {
  if (args.isEmpty) {
    print('Usage: dart pself-kdv.dart <file1> <file2> ...');
    exit(1);
  }

  final verifier = KdvVerifier();
  final sections = await loadFilesAsSections(args);
  verifier.loadInitialFingerprints(sections);

  // Simulate second check (e.g., after recompile)
  print('\n[VERIFYING AGAIN]');
  for (final entry in sections.entries) {
    verifier.verify(entry.key, entry.value);
  }
}
