import 'package:plugin_platform_interface/plugin_platform_interface.dart';
import 'auroprint_method_channel.dart';
import 'models/auroprint_result.dart';

abstract class AuroprintPlatform extends PlatformInterface {
  AuroprintPlatform() : super(token: _token);

  static final Object _token = Object();

  static AuroprintPlatform _instance = MethodChannelAuroprint();

  static AuroprintPlatform get instance => _instance;

  static set instance(AuroprintPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<AuroprintResult> generateAuroprint() {
    throw UnimplementedError('generateAuroprint() has not been implemented.');
  }

  Future<bool> isHardwareBackedAvailable() {
    throw UnimplementedError('isHardwareBackedAvailable() has not been implemented.');
  }

  Future<void> resetKey() {
    throw UnimplementedError('resetKey() has not been implemented.');
  }

  Future<String> requestIntegrityToken({
    required String nonce,
    int? cloudProjectNumber,
  }) {
    throw UnimplementedError('requestIntegrityToken() has not been implemented.');
  }
}
