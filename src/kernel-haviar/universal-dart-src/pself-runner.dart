import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';

import 'package:crypto/crypto.dart';

enum SectionType { elf, pe, macho }

class PselfHeader {
  static const int MAGIC = 0x5053454C; // 'PSEL'
  final int version;
  final int sectionCount;

  PselfHeader({required this.version, required this.sectionCount});

  static PselfHeader fromBytes(Uint8List bytes) {
    final data = ByteData.sublistView(bytes);
    final magic = data.getUint32(0);
    if (magic != MAGIC) throw Exception('Invalid PSELF magic');
    final version = data.getUint32(4);
    final count = data.getUint32(8);
    return PselfHeader(version: version, sectionCount: count);
  }
}

class SectionEntry {
  final SectionType type;
  final String name;
  final int offset;
  final int length;
  final List<int> hash;

  SectionEntry({
    required this.type,
    required this.name,
    required this.offset,
    required this.length,
    required this.hash,
  });

  static SectionEntry fromBytes(Uint8List bytes) {
    final type = SectionType.values[bytes[0]];
    final nameBytes = bytes.sublist(1, 33);
    final name = utf8.decode(nameBytes.where((b) => b != 0).toList());
    final data = ByteData.sublistView(bytes, 33, 41);
    final offset = data.getUint32(0);
    final length = data.getUint32(4);
    final hash = bytes.sublist(41, 73);
    return SectionEntry(
      type: type,
      name: name,
      offset: offset,
      length: length,
      hash: hash,
    );
  }

  bool verifyHash(Uint8List content) {
    final computed = sha256.convert(content).bytes;
    if (computed.length != hash.length) return false;
    for (int i = 0; i < computed.length; i++) {
      if (computed[i] != hash[i]) return false;
    }
    return true;
  }
}

class PselfRunner {
  final Uint8List data;
  late final PselfHeader header;
  late final List<SectionEntry> sections;

  PselfRunner(this.data) {
    header = PselfHeader.fromBytes(data.sublist(0, 12));
    sections = [];

    final sectionSize = 73;
    final start = 12;
    for (int i = 0; i < header.sectionCount; i++) {
      final off = start + i * sectionSize;
      final secBytes = data.sublist(off, off + sectionSize);
      final sec = SectionEntry.fromBytes(secBytes);
      sections.add(sec);
    }
  }

  void run() {
    print('PSELF v${header.version}, sections: ${header.sectionCount}');

    final osType = _detectOs();
    print('Detected OS: $osType');

    for (var sec in sections) {
      print('Section: ${sec.name} Type: ${sec.type} Offset: ${sec.offset} Length: ${sec.length}');
      final content = data.sublist(sec.offset, sec.offset + sec.length);

      if (!sec.verifyHash(Uint8List.fromList(content))) {
        print('[ERROR] Hash mismatch for section ${sec.name}');
        continue;
      }

      if (_isCompatible(sec.type, osType)) {
        print('[INFO] Loading compatible section "${sec.name}" for $osType');
        _loadSection(content, sec.type);
        return; // sadece uyumlu ilk section yüklendi varsayımı
      }
    }

    print('[ERROR] No compatible section found for this OS.');
  }

  String _detectOs() {
    if (Platform.isLinux) return 'linux';
    if (Platform.isWindows) return 'windows';
    if (Platform.isMacOS) return 'macos';
    return 'unknown';
  }

  bool _isCompatible(SectionType sectionType, String os) {
    switch (os) {
      case 'linux':
        return sectionType == SectionType.elf;
      case 'windows':
        return sectionType == SectionType.pe;
      case 'macos':
        return sectionType == SectionType.macho;
      default:
        return false;
    }
  }

void _loadSection(Uint8List content, SectionType type) {
  final outputExt = {
    SectionType.elf: '.elf.pself',
    SectionType.pe: '.exe.pself',
    SectionType.macho: '.mach.pself',
  }[type]!;

  final fileName = 'output_$outputExt';
  final outFile = File(fileName);
  outFile.writeAsBytesSync(content);

  print('[INFO] Section written as $fileName (converted for ${type.name.toUpperCase()})');
}

void main(List<String> args) {
  if (args.isEmpty) {
    print('Usage: dart pself-runner.dart <pself-file>');
    exit(1);
  }

  final filePath = args[0];
  final fileData = File(filePath).readAsBytesSync();

  final runner = PselfRunner(fileData);
  runner.run();
}
