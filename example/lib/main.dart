/// Copyright (C) 2018-2022 Jason C.H
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Lesser General Public
/// License as published by the Free Software Foundation; either
/// version 2.1 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Lesser General Public License for more details.
import 'package:flutter/material.dart';
import 'package:flutter_vpn/flutter_vpn.dart';
import 'package:flutter_vpn/state.dart';
import 'package:flutter/services.dart'; // <- Added for SytemNavigator

void main() => runApp(const MyApp());

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final _addressController = TextEditingController();
  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();

  var state = FlutterVpnState.disconnected;
  CharonErrorState? charonState = CharonErrorState.NO_ERROR;

  @override
  void initState() {
    FlutterVpn.prepare();
    FlutterVpn.onStateChanged.listen((s) => setState(() => state = s));
    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    
    // <- Added colors for visibility
    Color textColor = Colors.black;
    if('$state' == 'FlutterVpnState.connecting') {
      textColor = Colors.orange;
    } else if ('$state' == 'FlutterVpnState.connected') {
      textColor = Colors.green;
    } else if ('$state' == 'FlutterVpnState.disconnected') {
      textColor = Colors.blue;
    } else if ('$state' == 'FlutterVpnState.error') {
      textColor = Colors.red;
    }
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Flutter VPN'),
          actions: <Widget>[
            PopupMenuButton<String>(
              onSelected: (String result) {
                // Handle the menu selection
                if (result == 'Show Certificates') {
                  // Navigate to the settings page or handle settings logic
                  print('Show Certificates');
                  FlutterVpn.fetchCertificates();

                // } else if (result == 'Credits') {
                //   // Handle credits logic
                //   print('Credits selected');
                
                } else if (result == 'Exit') {
                  // Handle exit logic
                  print('Exit selected');
                  // exit(0);
                  /*await*/ FlutterVpn.disconnect(); // Can only await in async function
                  SystemNavigator.pop(); // to exit the app

                }
              },
              itemBuilder: (BuildContext context) {
                return <PopupMenuEntry<String>>[
                  const PopupMenuItem<String>(
                    value: 'Show Certificates',
                    child: Text('Show Certificates'),
                  ),
                  
                  // const PopupMenuItem<String>(
                  //   value: 'Credits',
                  //   child: Text('Credits'),
                  // ),

                  const PopupMenuItem<String>(
                    value: 'Exit',
                    child: Text('Exit'),
                  ),
                ];
              },
            ),
          ],
        ),

        body: ListView(
          padding: const EdgeInsets.all(12),
          children: <Widget>[
            Text.rich(
              TextSpan(
                children: [
                  const TextSpan(
                    text: 'Current State: ',
                    style: TextStyle(color: Colors.black), // Default color
                  ),
                  TextSpan(
                    text: '$state', // The state part
                    style: TextStyle(color: textColor), // Apply the dynamic color
                  ),
                ],
              ),
            ),
            Text('Current Charon State: $charonState'),
            TextFormField(
              controller: _addressController,
              decoration: const InputDecoration(icon: Icon(Icons.map_outlined)),
            ),
            TextFormField(
              controller: _usernameController,
              decoration: const InputDecoration(
                icon: Icon(Icons.person_outline),
              ),
            ),
            TextFormField(
              controller: _passwordController,
              obscureText: true,
              decoration: const InputDecoration(icon: Icon(Icons.lock_outline)),
            ),
            ElevatedButton(
              child: const Text('Connect'),
              onPressed: () => FlutterVpn.connectIkev2EAP(
                server: _addressController.text,
                username: _usernameController.text,
                password: _passwordController.text,
              ),
            ),
            ElevatedButton(
              child: const Text('Disconnect'),
              onPressed: () => FlutterVpn.disconnect(),
            ),
            ElevatedButton(
              child: const Text('Update State'),
              onPressed: () async {
                var newState = await FlutterVpn.currentState;
                setState(() => state = newState);
                print('Updated State!');
              },
            ),
            ElevatedButton(
              child: const Text('Update Charon State'),
              onPressed: () async {
                var newState = await FlutterVpn.charonErrorState;
                setState(() => charonState = newState);
                print('Updated Charon State!');
              },
            ),
            
            // <- Added
            // Button sends command to FlutterVpn method channel to
            // fetch certificates available in the smartphone.
            // Only android supported, iOS pending.
            // Pressing the button prints the certificates in 
            // debug console. To view in app ui, need to revamp
            // main app window for viewing certificate list and
            // changing method channels to pass strings.
            // <- Commented. 
            // Shifted to pop up window in top right corner
            // 
            // const ElevatedButton(
            //     onPressed: FlutterVpn.fetchCertificates,
            //     child: Text('Show Certificates'),
            // ),
          ],
        ),
      ),
    );
  }

}
