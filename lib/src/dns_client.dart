import 'dart:async';
import 'package:better_dart_ip/ip.dart';
import 'package:universal_io/io.dart';

import 'dns_packet.dart';
import 'http_dns_client.dart';
import 'udp_dns_client.dart';

/// Abstract superclass of DNS clients.
///
/// Commonly used implementations:
///   * [UdpDnsClient]
///   * [HttpDnsClient]
abstract class DnsClient {
  static const Duration defaultTimeout = Duration(seconds: 5);

  /// Queries resource records for the given host. By default, returns IP addresses.
  /// For other record types (e.g., MX, TXT), the returned list will be empty since
  /// `lookup` only returns IP addresses. Use [lookupPacket] for full answers.
  Future<List<IpAddress>> lookup(String name,
      {InternetAddressType type = InternetAddressType.any,
        DnsRecordType recordType = DnsRecordType.a});

  /// Queries resource records for the given host and record type, returning the full DNS packet.
  /// This allows you to retrieve any DNS record (A, AAAA, CNAME, MX, TXT, etc.).
  Future<DnsPacket> lookupPacket(String name,
      {InternetAddressType type = InternetAddressType.any,
        DnsRecordType recordType = DnsRecordType.a}) async {
    // Default implementation tries IP-based lookup. Override in subclasses.
    final list = await lookup(name, type: type, recordType: recordType);
    final result = DnsPacket.withResponse();
    result.answers = list.map((ipAddress) {
      final t = ipAddress is Ip4Address
          ? DnsResourceRecord.typeIp4
          : DnsResourceRecord.typeIp6;
      return DnsResourceRecord.withAnswer(
          name: name, type: t, data: ipAddress.toImmutableBytes());
    }).toList();
    return result;
  }

  /// Handles a DNS packet (e.g., from a server) and returns a response packet, if available.
  Future<DnsPacket?> handlePacket(DnsPacket packet, {Duration? timeout}) async {
    if (packet.questions.isEmpty) {
      return null;
    }

    // If there's only one question, we can directly handle it.
    if (packet.questions.length == 1) {
      final question = packet.questions.single;
      final recordType = question.type; // The actual DNS record type requested.
      switch (recordType) {
        case DnsRecordType.a:
        // A record
          return lookupPacket(question.name,
              type: InternetAddressType.IPv4, recordType: recordType);
        case DnsRecordType.aaaa:
        // AAAA record
          return lookupPacket(question.name,
              type: InternetAddressType.IPv6, recordType: recordType);
        default:
        // Attempt to handle other record types by directly querying them
          return lookupPacket(question.name, recordType: recordType);
      }
    }

    // If multiple questions, handle them all.
    final result = DnsPacket.withResponse();
    result.id = packet.id;
    result.answers = <DnsResourceRecord>[];
    final futures = <Future>[];

    for (var question in packet.questions) {
      // If it's A or AAAA, map to InternetAddressType. Otherwise, just use ANY.
      var addrType = InternetAddressType.any;
      if (question.type == DnsRecordType.a) {
        addrType = InternetAddressType.IPv4;
      } else if (question.type == DnsRecordType.aaaa) {
        addrType = InternetAddressType.IPv6;
      }
      futures.add(lookupPacket(
        question.name,
        type: addrType,
        recordType: question.type,
      ).then((packet) {
        result.answers.addAll(packet.answers);
      }));
    }

    await Future.wait(futures).timeout(timeout ?? defaultTimeout);
    return result;
  }
}

/// Uses system DNS lookup method.
class SystemDnsClient extends DnsClient {
  @override
  Future<List<IpAddress>> lookup(String host,
      {InternetAddressType type = InternetAddressType.any,
        DnsRecordType recordType = DnsRecordType.a}) async {
    // The system lookup only supports A/AAAA lookups via InternetAddress.
    // If a non-IP record type is requested, return empty.
    if (recordType != DnsRecordType.a && recordType != DnsRecordType.aaaa) {
      return <IpAddress>[];
    }

    final addresses = await InternetAddress.lookup(host, type: type);
    return addresses
        .map((item) => IpAddress.fromBytes(item.rawAddress))
        .toList();
  }
}

/// Superclass of packet-based clients.
///
/// See:
///   * [UdpDnsClient]
///   * [HttpDnsClient]
abstract class PacketBasedDnsClient extends DnsClient {
  @override
  Future<List<IpAddress>> lookup(String host,
      {InternetAddressType type = InternetAddressType.any,
        DnsRecordType recordType = DnsRecordType.a}) async {
    final packet = await lookupPacket(host, type: type, recordType: recordType);
    final result = <IpAddress>[];

    // For non-IP record types, we can't produce IpAddresses directly.
    // We'll only parse Ip4/Ip6 answers.
    for (var answer in packet.answers) {
      if (answer.name == host) {
        if (answer.type == DnsResourceRecord.typeIp4 ||
            answer.type == DnsResourceRecord.typeIp6) {
          final ipAddress = IpAddress.fromBytes(answer.data);
          result.add(ipAddress);
        }
      }
    }

    return result;
  }

  @override
  Future<DnsPacket> lookupPacket(String host,
      {InternetAddressType type = InternetAddressType.any,
        DnsRecordType recordType = DnsRecordType.a});
}

/// An exception that indicates failure by [DnsClient].
class DnsClientException implements Exception {
  final String message;

  DnsClientException(this.message);

  @override
  String toString() => message;
}

/// A DNS client that delegates operations to another client.
class DelegatingDnsClient implements DnsClient {
  final DnsClient client;

  DelegatingDnsClient(this.client);

  @override
  Future<List<IpAddress>> lookup(String host,
      {InternetAddressType type = InternetAddressType.any,
        DnsRecordType recordType = DnsRecordType.a}) {
    return client.lookup(host, type: type, recordType: recordType);
  }

  @override
  Future<DnsPacket?> handlePacket(DnsPacket packet, {Duration? timeout}) {
    return client.handlePacket(packet, timeout: timeout);
  }

  @override
  Future<DnsPacket> lookupPacket(String host,
      {InternetAddressType type = InternetAddressType.any,
        DnsRecordType recordType = DnsRecordType.a}) {
    return client.lookupPacket(host, type: type, recordType: recordType);
  }
}
