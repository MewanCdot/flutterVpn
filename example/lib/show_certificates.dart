import 'package:flutter/material.dart';

class ShowCertificate extends StatefulWidget {
  const ShowCertificate({Key? key}) : super(key: key);

  @override
  State<ShowCertificate> createState() => _ShowCertificateState();
}

class _ShowCertificateState extends State<ShowCertificate> {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text("Certificates"),
      ),
      body: Center(
        child: ElevatedButton(
          onPressed: () {
            // This will navigate back to the previous screen
            Navigator.pop(context);
          },
          child: const Text("Go Back"),
        ),
      ),
    );
  }
}