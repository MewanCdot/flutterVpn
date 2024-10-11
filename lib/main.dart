import 'dart:ffi';

import 'package:flutter/material.dart';
import 'styles/theme.dart';
import 'method_channels/method_channel.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'CDOT Quantum Secure Network Client',
      theme: lightTheme,
      darkTheme: darkTheme,
      themeMode: ThemeMode.system,
      home: const MyHomePage(),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key});

  static const temp = 'placeholder Text';

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {

  // Text Editting controllers for text fields
  final _serverAddressController = TextEditingController();
  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();

  void _disposeCreds() {
    _serverAddressController.dispose();
    _usernameController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  @override
  void initState() {
    // TODO: implement initState
    // HelperMethod.init();
    // HelperMethod.onStateChanged.listen((s) => setState(() => state = s));
    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('CDOT Quantum Secure Network Client'),
      ),
      body: Column(
        children: [
          // Status Container
          Container(
            color: Theme.of(context).primaryColor,
            width: double.infinity,
            height: 50,
            alignment: Alignment.center, // Center the text vertically
            child: const Text(
              'Status: ${MyHomePage.temp}',
              style: TextStyle(
                // color: Theme.of(context).textTheme.bodyLarge!.color, // <- color not set properly
                fontSize: 16, // Adjust the font size if needed
              ),
            ),
          ),
          
          // Form Fields
          Padding(
            padding: const EdgeInsets.all(8.0),
            child: Column(
              children: [
                TextFormField(
                  controller: _serverAddressController,
                  decoration: const InputDecoration(
                    icon: Icon(Icons.map_outlined),
                    labelText: 'Server Address', // You can add labels for better UI
                  ),
                ),
                TextFormField(
                  controller: _usernameController,
                  decoration: const InputDecoration(
                    icon: Icon(Icons.person_outlined),
                    labelText: 'Username',
                  ),
                ),
                TextFormField(
                  controller: _passwordController,
                  obscureText: true,
                  decoration: const InputDecoration(
                    icon: Icon(Icons.lock_outline),
                    labelText: 'Password',
                  ),
                ),
                const SizedBox( // Adding whitespace
                  height: 10,
                ),
                Container(
                  width: double.infinity, // Full width
                  child: ElevatedButton(
                    onPressed: () => Helper.connectToServer(
                      serverAddress: _serverAddressController.text,
                      username: _usernameController.text,
                      password: _passwordController.text,
                    ),
                    child: const Text('Connect'),
                  ),
                ),
                Container(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: () => Helper.disconnectFromServer(),
                    child: const Text('Disconnect'),
                  ),
                ),
              ],
            ),
          ),
        ],
      )

    );
  }
}