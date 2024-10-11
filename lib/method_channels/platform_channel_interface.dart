import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_vpn_project/method_channels/method_channel_interface.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

// Define the platform interface
abstract class PlatformChannelHelper extends PlatformInterface {
  // Constructor
  PlatformChannelHelper() : super(token: _token);

  static final Object _token = Object();

  // Get the instance of the platform
  static PlatformChannelHelper _instance = MethodChannelHelper();

  static PlatformChannelHelper get instance => _instance;

  // Allow setting a custom implementation for testing
  static set instance(PlatformChannelHelper instance) {
    _instance = instance;
  }

  // Define abstract methods for platform-specific functionality
  Future<void> connectToServer(String serverAddress, String username, String password) async => throw UnimplementedError();
  Future<void> disconnectFromServer() async => throw UnimplementedError();
}
