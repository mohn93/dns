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

import 'dart:async';
import 'dart:convert' as convert;

import 'package:better_dart_ip/ip.dart';
import 'package:meta/meta.dart';
import 'package:universal_io/io.dart';

import 'dns_client.dart';
import 'dns_packet.dart';
import 'udp_dns_client.dart';

/// DNS client that uses DNS-over-HTTPS protocol supported by Google, Cloudflare, etc.
class HttpDnsClient extends PacketBasedDnsClient {
  /// URL of the DNS-over-HTTPS service (without query parameters).
  final String url;
  final String _urlHost;

  /// Client to resolve the host of the DNS-over-HTTPS service if needed.
  final DnsClient? urlClient;

  /// Whether to hide client IP address from the authoritative server.
  final bool maximalPrivacy;

  /// Default timeout for operations.
  final Duration? timeout;

  HttpDnsClient(this.url, {this.timeout, this.maximalPrivacy = false, this.urlClient})
      : _urlHost = Uri.parse(url).host {
    if (url.contains('?')) {
      throw ArgumentError.value(url, 'url');
    }
  }

  /// Constructs a DNS-over-HTTPS client using Google's DNS service.
  HttpDnsClient.google({
    Duration? timeout,
    bool maximalPrivacy = false,
    DnsClient? urlClient,
  }) : this(
    'https://dns.google.com/resolve',
    timeout: timeout,
    maximalPrivacy: maximalPrivacy,
    urlClient: urlClient,
  );

  @override
  Future<DnsPacket> lookupPacket(
      String host, {
        InternetAddressType type = InternetAddressType.any,
        DnsRecordType recordType = DnsRecordType.a,
      }) async {
    // If we are resolving the host of the DNS-over-HTTPS service itself
    if (host == _urlHost) {
      final selfClient = urlClient ?? UdpDnsClient.google();
      return selfClient.lookupPacket(host, type: type, recordType: recordType);
    }

    // Construct query URL
    var queryUrl = '$url?name=${Uri.encodeQueryComponent(host)}';

    // Determine the query type based on recordType
    // You can extend this for other record types as needed.
    String queryTypeParam;
    switch (recordType) {
      case DnsRecordType.a:
        queryTypeParam = 'A';
        break;
      case DnsRecordType.aaaa:
        queryTypeParam = 'AAAA';
        break;
      case DnsRecordType.ns:
        queryTypeParam = 'NS';
        break;
      case DnsRecordType.cname:
        queryTypeParam = 'CNAME';
        break;
      case DnsRecordType.mx:
        queryTypeParam = 'MX';
        break;
      case DnsRecordType.txt:
        queryTypeParam = 'TXT';
        break;
      case DnsRecordType.any:
        queryTypeParam = 'ANY';
        break;
      default:
      // If we don't know the type, default to ANY
        queryTypeParam = 'ANY';
    }
    queryUrl += '&type=$queryTypeParam';

    // Add optional privacy parameter
    if (maximalPrivacy) {
      queryUrl += '&edns_client_subnet=0.0.0.0/0';
    }

    final httpClient = HttpClient();
    final request = await httpClient.getUrl(Uri.parse(queryUrl));
    final response = await request.close();
    if (response.statusCode != 200) {
      throw StateError(
          'HTTP response was ${response.statusCode} (${response.reasonPhrase}). URL was: $queryUrl');
    }

    final contentType = response.headers.contentType;
    if (contentType != null) {
      final mime = contentType.mimeType;
      if (mime != 'application/json' && mime != 'application/x-javascript') {
        throw StateError(
            'HTTP response content type was $contentType. URL was: $queryUrl');
      }
    }

    final data = await convert.utf8.decodeStream(response);
    final json = convert.json.decode(data);

    return decodeDnsPacket(json);
  }

  /// Converts JSON object to [DnsPacket].
  @visibleForTesting
  DnsPacket decodeDnsPacket(Object json) {
    if (json is Map) {
      final result = DnsPacket.withResponse();
      for (var key in json.keys) {
        final value = json[key];

        switch (key) {
          case 'Status':
            result.responseCode = (value as num).toInt();
            break;
          case 'AA':
            result.isAuthorativeAnswer = value as bool;
            break;
          case 'ID':
            result.id = (value as num).toInt();
            break;
          case 'QR':
            result.isResponse = value as bool;
            break;
          case 'RA':
            result.isRecursionAvailable = value as bool;
            break;
          case 'RD':
            result.isRecursionDesired = value as bool;
            break;
          case 'TC':
            result.isTruncated = value as bool;
            break;
          case 'Question':
            final questions = <DnsQuestion>[];
            result.questions = questions;
            if (value is List) {
              for (var item in value) {
                questions.add(decodeDnsQuestion(item));
              }
            }
            break;
          case 'Answer':
            final answers = <DnsResourceRecord>[];
            result.answers = answers;
            if (value is List) {
              for (var item in value) {
                answers.add(decodeDnsResourceRecord(item));
              }
            }
            break;
          case 'Additional':
            final additionalRecords = <DnsResourceRecord>[];
            result.additionalRecords = additionalRecords;
            if (value is List) {
              for (var item in value) {
                additionalRecords.add(decodeDnsResourceRecord(item));
              }
            }
            break;
        }
      }
      return result;
    } else {
      throw ArgumentError.value(json, 'json', 'Must be a Map');
    }
  }

  /// Converts JSON object to [DnsQuestion].
  @visibleForTesting
  DnsQuestion decodeDnsQuestion(Object json) {
    if (json is Map) {
      final result = DnsQuestion();
      for (var key in json.keys) {
        final value = json[key];
        switch (key) {
          case 'name':
            result.name = _trimDotSuffix(value as String);
            break;
          case 'type':
          // If provided, set the question type
          // Google's DOH might return a numeric type code.
            if (value is num) {
              result.type = DnsRecordType.fromInt(value.toInt());
            }
            break;
        }
      }
      return result;
    } else {
      throw ArgumentError.value(json, 'json', 'Must be a Map');
    }
  }

  /// Converts JSON object to [DnsResourceRecord].
  @visibleForTesting
  DnsResourceRecord decodeDnsResourceRecord(Object json) {
    if (json is Map) {
      final result = DnsResourceRecord();
      String? dataString;
      for (var key in json.keys) {
        final value = json[key];
        switch (key) {
          case 'name':
            result.name = _trimDotSuffix(value as String);
            break;
          case 'type':
            result.type = (value as num).toInt();
            break;
          case 'TTL':
            result.ttl = (value as num).toInt();
            break;
          case 'data':
          // Store the data for handling after we know the type
            dataString = value as String;
            break;
        }
      }

      if (dataString != null) {
        // Decode data based on the record type
        if (result.type == DnsResourceRecord.typeIp4 ||
            result.type == DnsResourceRecord.typeIp6) {
          // IP addresses
          result.data = IpAddress.parse(dataString).toImmutableBytes();
        } else {
          // For non-IP records (e.g., CNAME, TXT, MX), we store as UTF-8 bytes.
          // You may need more sophisticated handling per type.
          result.data = dataString.codeUnits;
        }
      }

      return result;
    } else {
      throw ArgumentError.value(json, 'json', 'Must be a Map');
    }
  }

  static String _trimDotSuffix(String s) {
    if (s.endsWith('.')) {
      return s.substring(0, s.length - 1);
    }
    return s;
  }
}
