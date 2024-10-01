package io.xdea.flutter_vpn
import java.util.Base64
import android.util.Log
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.Result
import org.strongswan.android.logic.TrustedCertificateManager

class MyNewPlugin : FlutterPlugin, MethodChannel.MethodCallHandler {
    private lateinit var channel: MethodChannel

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        // Create a new MethodChannel with a unique name
        channel = MethodChannel(binding.binaryMessenger, "my_new_plugin")
        channel.setMethodCallHandler(this) // Set the method call handler
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "getTrustedCertificates" -> {
                // Call the function and handle the result
                val certificates = getTrustedCertificates()
                if (certificates != null) {
                    result.success(certificates) // Send the certificates back to Flutter
                } else {
                    result.success(null) // Handle the case when there are no certificates
                }
            }
            else -> {
                result.notImplemented() // Handle unsupported method calls
            }
        }
    }

    private fun getTrustedCertificates(): List<String>? {
        val certs = ArrayList<String>()
        val certman = TrustedCertificateManager.getInstance().load() // Load the certificate manager
        try {
            // Assuming you have a way to access the current certificate alias
            val alias = "My Alias" // Adjust as necessary
            if (alias != null) {
                val cert = certman.getCACertificateFromAlias(alias)
                if (cert != null) {
                    // Encode to Base64 and add to the list
                    certs.add(Base64.getEncoder().encodeToString(cert.encoded))
                }
            } else {
                for (cert in certman.getAllCACertificates().values) {
                    certs.add(Base64.getEncoder().encodeToString(cert.encoded))
                }
            }
            // Return the list of certificates
            return certs
        } catch (e: Exception) {
            e.printStackTrace()
            return null // Return null on failure
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null) // Clean up the channel on detachment
    }
}
