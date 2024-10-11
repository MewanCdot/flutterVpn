package com.example.flutter_vpn_project;

import androidx.annotation.NonNull;
import io.flutter.embedding.android.FlutterActivity;
import io.flutter.embedding.engine.FlutterEngine;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugins.GeneratedPluginRegistrant;

public class MainActivity extends FlutterActivity {
    // Channel name
    private static final String CHANNEL = "flutter_vpn";

    @Override
    public void configureFlutterEngine(@NonNull FlutterEngine flutterEngine) {
        super.configureFlutterEngine(flutterEngine);
        GeneratedPluginRegistrant.registerWith(flutterEngine);

        new MethodChannel(flutterEngine.getDartExecutor().getBinaryMessenger(), CHANNEL)
            .setMethodCallHandler((call, result) -> {
                if (call.method.equals("connect")) {
                    // Call your VPN start method here
                    // to be implemented
                    result.success("Connection Initiated");
                } else if (call.method.equals("disconnect")) {
                    // Call your VPN stop method here
                    // to be implemented
                    result.success("Disconnect Initiated");
                } else {
                    result.notImplemented();
                }
            });

    }
}
