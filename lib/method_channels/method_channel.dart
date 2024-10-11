import 'platform_channel_interface.dart';

class Helper {
  
  // connect to server method
  static Future<void> connectToServer({
    required String serverAddress,
    required String username,
    required String password,
  }) => PlatformChannelHelper.instance.connectToServer(serverAddress, username, password);

  // disconnect to server method
  static Future<void> disconnectFromServer() => PlatformChannelHelper.instance.disconnectFromServer();
}