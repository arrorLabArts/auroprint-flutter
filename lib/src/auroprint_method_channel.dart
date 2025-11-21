import 'package:flutter/services.dart';
import 'auroprint_platform_interface.dart';
import 'models/auroprint_result.dart';

class MethodChannelAuroprint extends AuroprintPlatform {
  static const MethodChannel _channel = MethodChannel('com.arrorlabarts.auroprint/channel');

  @override
  Future<AuroprintResult> generateAuroprint() async {
    final result = await _channel.invokeMethod<Map<dynamic, dynamic>>('generateAuroprint');
    if (result == null) {
      throw PlatformException(
        code: 'NULL_RESULT',
        message: 'Failed to generate auroprint',
      );
    }
    return AuroprintResult.fromMap(Map<String, dynamic>.from(result));
  }

  @override
  Future<bool> isHardwareBackedAvailable() async {
    final result = await _channel.invokeMethod<bool>('isHardwareBackedAvailable');
    return result ?? false;
  }

  @override
  Future<void> resetKey() async {
    await _channel.invokeMethod<void>('resetKey');
  }
}
