import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

enum SectionType { elf, pe, macho }

class PselfHeader {
  static const int MAGIC = 0x5053454C; // 'PSEL' ASCII
  final int version;
  final int sectionCount;

  PselfHeader({this.version = 1, required this.sectionCount});

  Uint8List toBytes() {
    final buffer = ByteData(12);
    buffer.setUint32(0, MAGIC);
    buffer.setUint32(4, version);
    buffer.setUint32(8, sectionCount);
    return buffer.buffer.asUint8List();
  }

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
  final List<int> hash; // SHA256 hash

  SectionEntry({
    required this.type,
    required this.name,
    required this.offset,
    required this.length,
    required this.hash,
  });

  Uint8List toBytes() {
    final nameBytes = utf8.encode(name);
    if (nameBytes.length > 32) {
      throw Exception('Section name too long, max 32 bytes');
    }
    final buffer = BytesBuilder();
    buffer.addByte(type.index);
    buffer.add(List.filled(32 - nameBytes.length, 0)); // pad name
    buffer.add(nameBytes);
    final tmp = ByteData(16);
    tmp.setUint32(0, offset);
    tmp.setUint32(4, length);
    buffer.add(tmp.buffer.asUint8List(0, 8));
    buffer.add(hash);
    return buffer.toBytes();
  }

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

  static List<int> computeHash(Uint8List content) {
    return sha256.convert(content).bytes;
  }
}

void main() {
  // Örnek section içeriği
  final elfSectionContent = Uint8List.fromList([1, 2, 3, 4, 5]);
  final elfSectionHash = SectionEntry.computeHash(elfSectionContent);

  // Section oluştur
  final section = SectionEntry(
    type: SectionType.elf,
    name: 'text',
    offset: 0,
    length: elfSectionContent.length,
    hash: elfSectionHash,
  );

  // Header oluştur
  final header = PselfHeader(version: 1, sectionCount: 1);

  // Serialize
  final headerBytes = header.toBytes();
  final sectionBytes = section.toBytes();

  // Yazdır
  print('Header bytes: $headerBytes');
  print('Section bytes: $sectionBytes');

  // Deserialize örneği
  final headerParsed = PselfHeader.fromBytes(headerBytes);
  final sectionParsed = SectionEntry.fromBytes(sectionBytes);

  print('Parsed header version: ${headerParsed.version}');
  print('Parsed section name: ${sectionParsed.name}');
  print('Parsed section hash (hex): ${sectionParsed.hash.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
}
