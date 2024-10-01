/**
 * Copyright (C) 2018-2022 Jason C.H
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

package io.xdea.flutter_vpn

import android.app.Activity.RESULT_OK
import android.app.Service
import android.content.ComponentName
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Bundle
import android.os.IBinder
import androidx.annotation.NonNull

//import java.util.Base64
import android.util.Base64

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry
import org.strongswan.android.logic.VpnStateService

class FlutterVpnPlugin : FlutterPlugin, MethodCallHandler, ActivityAware {
    private lateinit var activityBinding: ActivityPluginBinding

    /// The MethodChannel that will the communication between Flutter and native Android
    ///
    /// This local reference serves to register the plugin with the Flutter Engine and unregister it
    /// when the Flutter Engine is detached from the Activity
    private lateinit var channel: MethodChannel
    private lateinit var eventChannel: EventChannel

    private var vpnStateService: VpnStateService? = null
    private val vpnStateServiceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, service: IBinder) {
            vpnStateService = (service as VpnStateService.LocalBinder).service
            VpnStateHandler.vpnStateService = vpnStateService
            vpnStateService?.registerListener(VpnStateHandler)
        }

        override fun onServiceDisconnected(name: ComponentName) {
            vpnStateService = null
            VpnStateHandler.vpnStateService = null
        }
    }

    // Added my plugin here
    private fun getTrustedCertificates(): List<String>? {
        //Create an instance of VpnStateService
        val vpnStateService = VpnStateService()
        
        // Call the method to fetch trusted certificates
        val certificatesInfo = vpnStateService.fetchTrustedCertificates(activityBinding.activity.applicationContext)
        
        // Process the returned string and convert it into a list of Base64 encoded certificates
        val certs = mutableListOf<String>()
        
        if (certificatesInfo != null) {
            // Split the output by lines
            val lines = certificatesInfo.split("\n").filter { it.isNotBlank() }

            // Assuming the certificates are in a specific format
            for (line in lines) {
                // Check if the line contains a certificate (you can customize this condition)
                if (line.startsWith("Subject:")) {
                    // Extract the certificate (this may need customization)
                    // For this example, just encode the line for simplicity
                    val certData = line.substringAfter("Subject: ").trim()
                    // Convert to Base64 (if the data is in a string format that can be Base64 encoded)
                    val encodedCert = Base64.encodeToString(certData.toByteArray(), Base64.NO_WRAP)
                    certs.add(encodedCert)
                }
            }
        }
        
        return certs
    }
    //

    override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        // Load charon bridge
        System.loadLibrary("androidbridge")

        // Register method channel.
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "flutter_vpn")
        channel.setMethodCallHandler(this)

        // Register event channel to handle state change.
        eventChannel = EventChannel(flutterPluginBinding.binaryMessenger, "flutter_vpn_states")
        eventChannel.setStreamHandler(VpnStateHandler)

        flutterPluginBinding.applicationContext.bindService(
            Intent(flutterPluginBinding.applicationContext, VpnStateService::class.java),
            vpnStateServiceConnection,
            Service.BIND_AUTO_CREATE
        )

        // Added here. My plugin
        // Register method channel
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "my_new_plugin_channel")
        channel.setMethodCallHandler(this)

    }

    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        eventChannel.setStreamHandler(null)
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activityBinding = binding
    }

    override fun onDetachedFromActivity() {
    }

    override fun onDetachedFromActivityForConfigChanges() {
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activityBinding = binding
    }

    override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
        when (call.method) {
            "prepare" -> {
                val intent = VpnService.prepare(activityBinding.activity.applicationContext)
                if (intent != null) {
                    var listener: PluginRegistry.ActivityResultListener? = null
                    listener = PluginRegistry.ActivityResultListener { req, res, _ ->
                        result.success(req == 0 && res == RESULT_OK)
                        listener?.let { activityBinding.removeActivityResultListener(it) }
                        true
                    }
                    activityBinding.addActivityResultListener(listener)
                    activityBinding.activity.startActivityForResult(intent, 0)
                } else {
                    // Already prepared if intent is null.
                    result.success(true)
                }
            }
            "prepared" -> {
                val intent = VpnService.prepare(activityBinding.activity.applicationContext)
                result.success(intent == null)
            }
            "connect" -> {
                val intent = VpnService.prepare(activityBinding.activity.applicationContext)
                if (intent != null) {
                    // Not prepared yet.
                    result.success(false)
                    return
                }

                val args = call.arguments as Map<*, *>

                val profileInfo = Bundle()
                profileInfo.putString("VpnType", "ikev2-eap")
                profileInfo.putString("Name", args["Name"] as String)
                profileInfo.putString("Server", args["Server"] as String)
                profileInfo.putString("Username", args["Username"] as String)
                profileInfo.putString("Password", args["Password"] as String)
                if (args.containsKey("MTU"))  profileInfo.putInt("MTU", args["MTU"] as Int)
                if (args.containsKey("port")) profileInfo.putInt("Port", args["Port"] as Int)

                vpnStateService?.connect(profileInfo, true)
                result.success(true)
            }
            "getCurrentState" -> {
                if (vpnStateService?.errorState != VpnStateService.ErrorState.NO_ERROR)
                    result.success(4)
                else
                    result.success(vpnStateService?.state?.ordinal)
            }
            "getCharonErrorState" -> result.success(vpnStateService?.errorState?.ordinal)
            "disconnect" -> vpnStateService?.disconnect()

            // Added here
            "getTrustedCertificates" -> {
                val certificates = getTrustedCertificates()
                if (certificates != null) {
                    result.success(certificates)
                } else {
                    result.error("CERTIFICATE_ERROR", "Failed to retrieve certificates", null)
                }
            }
            //
            else -> result.notImplemented()
        }
    }
}
