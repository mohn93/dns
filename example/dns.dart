import 'dart:io';

import 'package:dart_dns/dart_dns.dart';
import 'dart:async';

Future<void> main(List<String> args) async {
  final client = UdpDnsClient(
    remoteAddress: InternetAddress('203.109.191.1'));
  final result =
      await client.lookupPacket('google.com', recordType: DnsRecordType.a);
  print('${result.answers.map(
        (t) => t.dataAsHumanReadableString(),
      ).join('\n ')}');
}
