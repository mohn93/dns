import 'dart:async';
import 'dart:collection';
import 'dart:math';

import 'package:better_dart_ip/ip.dart';
import 'package:dart_raw/raw.dart';
import 'package:universal_io/io.dart';

import 'dns_client.dart';
import 'dns_packet.dart';

/// EDNS(0) constants
const int typeOpt = 41; // OPT pseudo-record
const int defaultUdpPayloadSize = 4096; // Common EDNS0 buffer size

/// A standard DNS-over-UDP client implementation with EDNS(0) support.
class UdpDnsClient extends PacketBasedDnsClient {
  static final _portRandom = Random.secure();
  final InternetAddress remoteAddress;
  final int remotePort;
  final InternetAddress? localAddress;
  final int? localPort;
  final Duration? timeout;
  Future<RawDatagramSocket>? _socket;

  final LinkedList<_DnsResponseWaiter> _responseWaiters =
  LinkedList<_DnsResponseWaiter>();

  UdpDnsClient({
    required this.remoteAddress,
    this.remotePort = 53,
    this.localAddress,
    this.localPort,
    this.timeout,
  });

  factory UdpDnsClient.google() {
    return UdpDnsClient(remoteAddress: InternetAddress('8.8.8.8'));
  }

  @override
  Future<DnsPacket> lookupPacket(
      String host, {
        InternetAddressType type = InternetAddressType.any,
        DnsRecordType recordType = DnsRecordType.a,
      }) async {
    final socket = await _getSocket();
    final dnsPacket = DnsPacket();

    // Set a random ID for this packet
    final packetId = Random().nextInt(0xFFFF);
    dnsPacket.id = packetId;

    dnsPacket.questions = [DnsQuestion(host: host, recordType: recordType)];

    // Set recursion desired
    dnsPacket.isRecursionDesired = true;

    // Add EDNS(0) OPT record in Additional section
    // This advertises extended capabilities and larger UDP payload size
    dnsPacket.additionalRecords = [
      _createOptRecord(),
    ];

    final responseWaiter = _DnsResponseWaiter(host, packetId);
    _responseWaiters.add(responseWaiter);

    // Send the DNS query packet
    final bytes = dnsPacket.toImmutableBytes();
    socket.send(bytes, remoteAddress, remotePort);

    // Set timeout for response
    final queryTimeout = timeout ?? DnsClient.defaultTimeout;
    responseWaiter.timer = Timer(queryTimeout, () {
      if (!responseWaiter.completer.isCompleted) {
        responseWaiter.unlink();
        responseWaiter.completer.completeError(
          TimeoutException("DNS query '$host' timed out after $queryTimeout"),
        );
      }
    });

    return responseWaiter.completer.future;
  }

  /// Creates an OPT record for EDNS(0) support.
  /// This tells the server we can handle larger responses (up to `defaultUdpPayloadSize` bytes).
  DnsResourceRecord _createOptRecord() {
    final opt = DnsResourceRecord();
    // The OPT RR's NAME is always the root (empty) and represented as a single 0-length label
    opt.nameParts = [];
    opt.type = typeOpt;
    // class field in OPT record is used for UDP payload size
    opt.classy = defaultUdpPayloadSize;
    // TTL is used for extended RCODE and flags, 0 for now
    opt.ttl = 0;
    // No data for basic EDNS(0) usage
    opt.data = [];
    return opt;
  }

  Future<RawDatagramSocket> _getSocket() async {
    if (_socket != null) {
      return _socket!;
    }
    final localAddr = localAddress;
    final localPrt = localPort;
    final socket = await _bindSocket(localAddr, localPrt);
    socket.listen((event) {
      if (event == RawSocketEvent.read) {
        final datagram = socket.receive();
        if (datagram == null) {
          return;
        }
        _receiveUdpPacket(datagram);
      }
    });
    _socket = Future.value(socket);
    return socket;
  }

  void _receiveUdpPacket(Datagram datagram) {
    // Decode the DNS packet from the received datagram
    final dnsPacket = DnsPacket();
    dnsPacket.decodeSelf(RawReader.withBytes(datagram.data));

    final packetId = dnsPacket.id;

    _DnsResponseWaiter? matchedWaiter;
    for (var query in _responseWaiters) {
      if (!query.completer.isCompleted && query.id == packetId) {
        matchedWaiter = query;
        break;
      }
    }

    if (matchedWaiter != null) {
      matchedWaiter.timer.cancel();
      matchedWaiter.unlink();

      // Check if truncated
      if (dnsPacket.isTruncated) {
        // If truncated, EDNS(0) is not enough or packet is too large
        // Consider retrying over TCP here if needed.
        // For demonstration:
        // matchedWaiter.completer.completeError(StateError("Truncated response. Consider TCP fallback."));
        // Or implement a TCP fallback lookup and then complete matchedWaiter.completer with that result.
      } else {
        matchedWaiter.completer.complete(dnsPacket);
      }
    }
  }

  /// Binds socket. If port is null, attempts 3 random ports before giving up.
  static Future<RawDatagramSocket> _bindSocket(
      InternetAddress? address, int? port) async {
    address ??= InternetAddress.anyIPv4;
    for (var n = 3; n > 0; n--) {
      try {
        return await RawDatagramSocket.bind(address, port ?? _randomPort());
      } catch (_) {
        if (n == 1) rethrow;
      }
    }
    throw StateError('Could not bind UDP socket after multiple attempts.');
  }

  static int _randomPort() {
    const min = 10000;
    return min + _portRandom.nextInt((1 << 16) - min);
  }
}

base class _DnsResponseWaiter extends LinkedListEntry<_DnsResponseWaiter> {
  final String host;
  final Completer<DnsPacket> completer = Completer<DnsPacket>();
  late Timer timer;
  final List<IpAddress> result = <IpAddress>[];

  final int id;

  _DnsResponseWaiter(this.host, this.id);
}
