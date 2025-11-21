import 'package:flutter/material.dart';
import 'package:auroprint/auroprint.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String _status = 'Press button to generate';
  AuroprintResult? _result;

  Future<void> _generateAuroprint() async {
    setState(() => _status = 'Generating...');

    try {
      final result = await Auroprint.generateAuroprint();
      setState(() {
        _result = result;
        _status = 'Success!';
      });
    } catch (e) {
      setState(() => _status = 'Error: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('Auroprint Example')),
        body: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              ElevatedButton(
                onPressed: _generateAuroprint,
                child: const Text('Generate Auroprint'),
              ),
              const SizedBox(height: 16),
              Text('Status: $_status'),
              if (_result != null) ...[
                const SizedBox(height: 16),
                Text('Device ID: ${_result!.deviceId.substring(0, 16)}...'),
                Text('Timestamp: ${_result!.timestamp}'),
                Text('Nonce: ${_result!.nonce}'),
                Text('Hardware-backed: ${_result!.isHardwareBacked}'),
                const SizedBox(height: 8),
                const Text('Payload:', style: TextStyle(fontWeight: FontWeight.bold)),
                Text(_result!.payload, style: const TextStyle(fontSize: 12)),
                const SizedBox(height: 8),
                const Text('Signature:', style: TextStyle(fontWeight: FontWeight.bold)),
                Text('${_result!.signature.substring(0, 50)}...',
                     style: const TextStyle(fontSize: 12)),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
