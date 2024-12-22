// Copyright 2019 Gohilla.com team.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:convert';

import 'package:better_dart_ip/foundation.dart';
import 'package:better_dart_ip/ip.dart';
import 'package:dart_raw/raw.dart';

const Protocol dns = Protocol('DNS');

void _writeDnsName(RawWriter writer, List<String> parts, int startIndex,
    Map<String, int>? offsets) {
  // Store pointer in the map
  if (offsets != null) {
    final key = parts.join('.');
    final existingPointer = offsets[key];
    if (existingPointer != null) {
      writer.writeUint16(0xC000 | existingPointer);
      return;
    }
    offsets[key] = writer.length - startIndex;
  }

  for (var i = 0; i < parts.length; i++) {
    final part = parts[i];

    // Find pointer
    if (i >= 1 && offsets != null) {
      final offset = offsets[parts.skip(i).join('.')];
      if (offset != null) {
        // Write pointer
        writer.writeUint16(0xc000 | offset);
        return;
      }
    }

    // Write length and string bytes
    writer.writeUint8(part.length);
    writer.writeUtf8Simple(part);
  }

  // Zero-length part means end of name parts
  writer.writeUint8(0);
}

List<String> _readDnsName(RawReader reader, int? startIndex) {
  var name = <String>[];
  while (reader.availableLengthInBytes > 0) {
    // Read length
    final length = reader.readUint8();

    if (length == 0) {
      // End of name
      break;
    } else if (length < 64) {
      // A label
      final value = reader.readUtf8(length);
      name.add(value);
    } else {
      // This is a pointer

      // Validate we received start index,
      // so we can actually handle pointers
      if (startIndex == null) {
        throw ArgumentError.notNull('startIndex');
      }

      // Calculate and validate index in the data
      final byte1 = reader.readUint8();
      final pointedIndex = startIndex + (((0x3F & length) << 8) | byte1);
      if (pointedIndex > reader.bufferAsByteData.lengthInBytes ||
          reader.bufferAsByteData.getUint8(pointedIndex) >= 64) {
        final index = reader.index - 2;
        throw StateError(
          'invalid pointer from index 0x${index.toRadixString(16)} (decimal: $index) to index 0x${pointedIndex.toRadixString(16)} ($pointedIndex)',
        );
      }

      final oldIndex = reader.index;
      reader.index = pointedIndex;

      // Read name
      final result = _readDnsName(reader, startIndex);

      reader.index = oldIndex;

      // Concatenate
      name.addAll(result);

      // End
      break;
    }
  }
  return name;
}

class DnsResourceRecord extends SelfCodec {
  static const int responseCodeNoError = 0;
  static const int responseCodeFormatError = 1;
  static const int responseCodeServerFailure = 2;
  static const int responseCodeNonExistentDomain = 3;
  static const int responseCodeNotImplemented = 4;
  static const int responseCodeQueryRefused = 5;
  static const int responseCodeNotInZone = 10;

  static String stringFromResponseCode(int code) {
    switch (code) {
      case responseCodeNoError:
        return 'No error';
      case responseCodeFormatError:
        return 'Format error';
      case responseCodeServerFailure:
        return 'Server failure';
      case responseCodeNonExistentDomain:
        return 'Non-existent domain';
      case responseCodeNotImplemented:
        return 'Not implemented';
      case responseCodeQueryRefused:
        return 'Query refused';
      case responseCodeNotInZone:
        return 'Not in the zone';
      default:
        return 'Unknown';
    }
  }

  /// A host address ("A" record).
  static const int typeIp4 = 1;

  /// Authoritative name server ("NS" record).
  static const int typeNameServer = 2;

  /// The canonical name for an alias ("CNAME" record).
  static const int typeCanonicalName = 5;

  /// Domain name pointer ("PTR" record).
  static const int typeDomainNamePointer = 12;

  /// Mail server ("MX" record) record.
  static const int typeMailServer = 15;

  /// Text record ("TXT" record).
  static const int typeText = 16;

  /// IPv6 host address record (AAAA).
  static const int typeIp6 = 28;

  /// Server discovery ("SRV" record).
  static const int typeServerDiscovery = 33;

  static String stringFromType(DnsRecordType value) {
    return DnsQuestion.stringFromType(value);
  }

  static const int classInternetAddress = 1;

  static String stringFromClass(int value) {
    return DnsQuestion.stringFromClass(value);
  }

  /// List of name parts.
  ///
  /// It can be an immutable value.
  List<String> nameParts = const <String>[];

  set name(String value) {
    nameParts = value.split('.');
  }

  String get name => nameParts.join('.');

  /// 16-bit type
  int type = typeIp4;

  /// 16-bit class
  int classy = classInternetAddress;

  /// 32-bit TTL
  int ttl = 0;

  /// Data
  List<int> data = const <int>[];

  DnsResourceRecord();

  DnsResourceRecord.withAnswer(
      {required String name, required this.type, required this.data}) {
    this.name = name;
    ttl = 600;
  }

  @override
  void encodeSelf(RawWriter writer,
      { int startIndex = 0 , Map<String, int>? pointers}) {
    // Write name
    // (a list of labels/pointers)
    _writeDnsName(
      writer,
      nameParts,
      startIndex,
      pointers,
    );

    // 2-byte type
    writer.writeUint16(type);

    // 2-byte class
    writer.writeUint16(classy);

    // 4-byte time-to-live
    writer.writeUint32(ttl);

    // 2-byte length of answer data
    writer.writeUint16(data.length);

    // Answer data
    writer.writeBytes(data);
  }

  @override
  void decodeSelf(RawReader reader, {int? startIndex}) {
    startIndex ??= 0;
    // Read name
    nameParts = _readDnsName(reader, startIndex);

    // 2-byte type
    type = reader.readUint16();

    // 2-byte class
    classy = reader.readUint16();

    // 4-byte time-to-live
    ttl = reader.readUint32();

    // 2-byte length
    final dataLength = reader.readUint16();

    // N-byte data
    data = reader.readUint8ListViewOrCopy(dataLength);
  }

  String dataAsHumanReadableString() {
    switch (type) {
      case typeText:
      // TXT records are a series of length-prefixed strings.
        final bytes = data;
        int i = 0;
        final parts = <String>[];
        while (i < bytes.length) {
          final length = bytes[i];
          i++;
          if (i + length > bytes.length) {
            // Malformed TXT data, break early.
            break;
          }
          final segment = bytes.sublist(i, i + length);
          i += length;
          // Decode the segment as UTF-8 text
          final text = utf8.decode(segment);
          parts.add(text);
        }
        return parts.join('');

      case typeIp4:
      // A record: data is 4 bytes representing IPv4 address
        if (data.length == 4) {
          return '${data[0]}.${data[1]}.${data[2]}.${data[3]}';
        }
        return 'Invalid A record data';

      case typeIp6:
      // AAAA record: data is 16 bytes representing IPv6 address
        if (data.length == 16) {
          final ip = IpAddress.fromBytes(data);
          return ip.toString();
        }
        return 'Invalid AAAA record data';

      case typeCanonicalName:
      case typeNameServer:
      case typeDomainNamePointer:
      // These contain domain names in the data, which may need parsing similar to _readDnsName.
      // If needed, implement parsing logic (currently the data might already have been read).
      // For simplicity, assume data is raw domain name string if needed.
      // Often, these are returned in the `nameParts` if the server returns them as answers.
      // If you need to decode from 'data' for these, implement a name decoder similar to the question decoding.
        return 'Domain name (CNAME/NS/PTR) not implemented';

      default:
      // For other types, just return a hex string or raw bytes for now.
        return 'Raw data: ${data.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ')}';
    }
  }

  @override
  int encodeSelfCapacity() {
    var n = 64;
    for (var part in nameParts) {
      n += 1 + part.length;
    }
    return n;
  }
}

class DnsPacket extends Packet {
  static const int opQuery = 0;
  static const int opInverseQuery = 1;
  static const int opStatus = 2;
  static const int opNotify = 3;
  static const int opUpdate = 4;

  int _v0 = 0;

  List<DnsQuestion> questions = const <DnsQuestion>[];
  List<DnsResourceRecord> answers = const <DnsResourceRecord>[];
  List<DnsResourceRecord> authorities = const <DnsResourceRecord>[];
  List<DnsResourceRecord> additionalRecords = const <DnsResourceRecord>[];

  DnsPacket() {
    op = opQuery;
    isRecursionDesired = true;
  }

  DnsPacket.withResponse({DnsPacket? request}) {
    op = opQuery;
    isResponse = true;
    if (request != null) {
      questions = <DnsQuestion>[];
    }
  }

  int get id => extractUint32Bits(_v0, 16, 0xFFFF);

  set id(int value) {
    _v0 = transformUint32Bits(_v0, 16, 0xFFFF, value);
  }

  bool get isAuthorativeAnswer => extractUint32Bool(_v0, 10);

  set isAuthorativeAnswer(bool value) {
    _v0 = transformUint32Bool(_v0, 10, value);
  }

  bool get isRecursionAvailable => extractUint32Bool(_v0, 7);

  set isRecursionAvailable(bool value) {
    _v0 = transformUint32Bool(_v0, 7, value);
  }

  bool get isRecursionDesired => extractUint32Bool(_v0, 8);

  set isRecursionDesired(bool value) {
    _v0 = transformUint32Bool(_v0, 8, value);
  }

  bool get isResponse => extractUint32Bool(_v0, 15);

  set isResponse(bool value) {
    _v0 = transformUint32Bool(_v0, 15, value);
  }

  bool get isTruncated => extractUint32Bool(_v0, 9);

  set isTruncated(bool value) {
    _v0 = transformUint32Bool(_v0, 9, value);
  }

  int get op => extractUint32Bits(_v0, 11, 0xF);

  set op(int value) {
    _v0 = transformUint32Bits(_v0, 11, 0xF, value);
  }

  @override
  Protocol get protocol => dns;

  int get reservedBits => 0x3 & (_v0 >> 4);

  int get responseCode => extractUint32Bits(_v0, 0, 0xF);

  set responseCode(int value) {
    _v0 = transformUint32Bits(_v0, 0, 0xF, value);
  }

  @override
  void encodeSelf(RawWriter writer) {
    final startIndex = writer.length;

    // 4-byte span at index 0
    writer.writeUint32(_v0);

    // 2-byte span at index 4
    writer.writeUint16(questions.length);

    // 2-byte span at index 6
    writer.writeUint16(answers.length);

    // 2-byte span at index 8
    writer.writeUint16(authorities.length);

    // 2-byte span at index 10
    writer.writeUint16(additionalRecords.length);

    // Name -> pointer
    final pointers = <String, int>{};

    for (var item in questions) {
      item.encodeSelf(
        writer,
        startIndex: startIndex,
        pointers: pointers,
      );
    }

    for (var item in answers) {
      item.encodeSelf(
        writer,
        startIndex: startIndex,
        pointers: pointers,
      );
    }

    for (var item in authorities) {
      item.encodeSelf(
        writer,
        startIndex: startIndex,
        pointers: pointers,
      );
    }

    for (var item in additionalRecords) {
      item.encodeSelf(
        writer,
        startIndex: startIndex,
        pointers: pointers,
      );
    }
  }

  @override
  void decodeSelf(RawReader reader) {
    // Clear existing values
    questions = <DnsQuestion>[];
    answers = <DnsResourceRecord>[];
    authorities = <DnsResourceRecord>[];
    additionalRecords = <DnsResourceRecord>[];

    // Fixed header
    final startIndex = reader.index;

    // 4-byte span at index 0
    _v0 = reader.readUint32();

    // 2-byte spans
    var questionsLength = reader.readUint16();
    var answersLength = reader.readUint16();
    var nameServerResourcesLength = reader.readUint16();
    var additionalResourcesLength = reader.readUint16();

    for (; questionsLength > 0; questionsLength--) {
      final item = DnsQuestion();
      item.decodeSelf(reader, startIndex: startIndex);
      questions.add(item);
    }

    for (; answersLength > 0; answersLength--) {
      final item = DnsResourceRecord();
      item.decodeSelf(reader, startIndex: startIndex);
      answers.add(item);
    }

    for (; nameServerResourcesLength > 0; nameServerResourcesLength--) {
      final item = DnsResourceRecord();
      item.decodeSelf(reader, startIndex: startIndex);
      authorities.add(item);
    }

    for (; additionalResourcesLength > 0; additionalResourcesLength--) {
      final item = DnsResourceRecord();
      item.decodeSelf(reader, startIndex: startIndex);
      additionalRecords.add(item);
    }
  }

  @override
  int encodeSelfCapacity() {
    var n = 64;
    for (var item in questions) {
      n += item.encodeSelfCapacity();
    }
    for (var item in answers) {
      n += item.encodeSelfCapacity();
    }
    for (var item in authorities) {
      n += item.encodeSelfCapacity();
    }
    for (var item in additionalRecords) {
      n += item.encodeSelfCapacity();
    }
    return n;
  }
}

enum DnsRecordType {
  a(1),
  ns(2),
  cname(5),
  mx(15),
  txt(16),
  aaaa(28),
  any(255),
  srv(33),
  ptr(12),
  mg(14),
  caa(257);
  final int value;
  const DnsRecordType(this.value);
  factory DnsRecordType.fromInt(int value) {
    switch (value) {
      case 1:
        return DnsRecordType.a;
      case 2:
        return DnsRecordType.ns;
      case 5:
        return DnsRecordType.cname;
      case 15:
        return DnsRecordType.mx;
      case 16:
        return DnsRecordType.txt;
      case 28:
        return DnsRecordType.aaaa;
      case 255:
        return DnsRecordType.any;
      case 33:
        return DnsRecordType.srv;
      case 12:
        return DnsRecordType.ptr;
      case 14:
        return DnsRecordType.mg;
      case 257:
        return DnsRecordType.caa;
      default:
        throw ArgumentError.value(value, 'value', 'Invalid DNS record type');
    }
  }
  String label() {
    switch (this) {
      case DnsRecordType.a:
        return 'A (IPv4)';
      case DnsRecordType.ns:
        return 'NS';
      case DnsRecordType.cname:
        return 'CNAME';
      case DnsRecordType.mx:
        return 'MX';
      case DnsRecordType.txt:
        return 'TXT';
      case DnsRecordType.aaaa:
        return 'AAAA (IPv6)';
      case DnsRecordType.any:
        return 'ANY';
      case DnsRecordType.srv:
        return 'SRV';
      case DnsRecordType.ptr:
        return 'PTR';
      case DnsRecordType.mg:
        return 'MG';
      case DnsRecordType.caa:
        return 'CAA';

      default:
        return 'type $this';
    }
  }
}
class DnsQuestion extends SelfCodec {

  static String stringFromType(DnsRecordType type) {
    switch (type) {
      case DnsRecordType.a:
        return 'A (IPv4)';
      case DnsRecordType.ns:
        return 'NS';
      case DnsRecordType.cname:
        return 'CNAME';
      case DnsRecordType.mx:
        return 'MX';
      case DnsRecordType.txt:
        return 'TXT';
      case DnsRecordType.aaaa:
        return 'AAAA (IPv6)';
      case DnsRecordType.any:
        return 'ANY';
      default:
        return 'type $type';
    }
  }

  // -------
  // Classes
  // -------

  static const int classInternetAddress = 1;

  static String stringFromClass(int type) {
    switch (type) {
      case classInternetAddress:
        return 'Internet address';
      default:
        return 'class $type';
    }
  }

  /// List of name parts.
  ///
  /// It can be an immutable value.
  List<String> nameParts = <String>[];

  set name(String value) {
    nameParts = value.split('.');
  }

  String get name => nameParts.join('.');

  /// 16-bit type
  DnsRecordType type = DnsRecordType.a;

  /// 16-bit class
  int classy = classInternetAddress;

  DnsQuestion({String? host, DnsRecordType recordType = DnsRecordType.a}) {
    if (host != null) {
      nameParts = host.split('.');
    }
    type = recordType;
  }

  @override
  void encodeSelf(RawWriter writer,
      {int startIndex = 0, Map<String, int>? pointers}) {
    // Write name
    _writeDnsName(
      writer,
      nameParts,
      startIndex,
      pointers,
    );

    // 2-byte type
    writer.writeUint16(type.value);

    // 2-byte class
    writer.writeUint16(classy);
  }

  @override
  void decodeSelf(RawReader reader, {int? startIndex}) {
    // Name
    nameParts = _readDnsName(reader, startIndex);

    // 2-byte question type
    type = DnsRecordType.fromInt(reader.readUint16());

    // 2-byte question class
    classy = reader.readUint16();
  }

  @override
  int encodeSelfCapacity() {
    var n = 16;
    for (var part in nameParts) {
      n += 1 + part.length;
    }
    return n;
  }
}
