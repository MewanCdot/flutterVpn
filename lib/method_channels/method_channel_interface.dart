import 'package:flutter/services.dart';
import 'package:flutter_vpn_project/method_channels/platform_channel_interface.dart';

class MethodChannelHelper extends PlatformChannelHelper{
  
  final methodChannel = const MethodChannel('flutter_vpn');

  @override
  Future<void> connectToServer(String serverAddress, String username, String password) async {
    try {
      final result = await methodChannel.invokeMethod('connect', {
      'Server': serverAddress,
      'Username': username,
      'Password': password,
      });
      print(result);
    } on PlatformException catch(e) {
      print('Error: ${e.message}');
    }
  }

  @override
  Future<void> disconnectFromServer() async {
    try {
      final result = await methodChannel.invokeMethod('disconnect');
      print(result);
    } on PlatformException catch(e) {
      print('Error: ${e.message}');
    }
  }

}