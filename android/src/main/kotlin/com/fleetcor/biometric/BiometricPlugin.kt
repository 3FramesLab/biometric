package com.fleetcor.biometric

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.core.hardware.fingerprint.FingerprintManagerCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.fleetcor.biometric.AuthenticationHelper.AuthCompletionHandler
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.FlutterPlugin.FlutterPluginBinding
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.embedding.engine.plugins.lifecycle.FlutterLifecycleAdapter
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.PluginRegistry.ActivityResultListener
import java.util.concurrent.atomic.AtomicBoolean

class BiometricPlugin
    : MethodCallHandler, FlutterPlugin, ActivityAware {

    private var activity: Activity? = null
        private set
    private var authHelper: AuthenticationHelper? = null

    val authInProgress = AtomicBoolean(false)

    // These are null when not using v2 embedding.
    private var channel: MethodChannel? = null
    private var lifecycle: Lifecycle? = null
    private var biometricManager: BiometricManager? = null
    private var keyguardManager: KeyguardManager? = null
    private var lockRequestResult: MethodChannel.Result? = null
    private val resultListener =
        ActivityResultListener { requestCode, resultCode, data ->
            if (requestCode == LOCK_REQUEST_CODE) {
                if (resultCode == Activity.RESULT_OK && lockRequestResult != null) {
                    authenticateSuccess(lockRequestResult!!)
                } else {
                    authenticateFail(lockRequestResult)
                }
                lockRequestResult = null
            }
            false
        }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            authenticate -> authenticate(call, result)
            getAvailableBiometrics -> getEnrolledBiometrics(result)
            isDeviceSupported -> isDeviceSupportedMethod(result)
            stopAuthentication -> stopAuthentication(result)
            deviceSupportsBiometrics -> deviceSupportsBiometrics(result)
            checkDeviceBiometricStatus -> isBiometricEnrolled(result)
            else -> result.notImplemented()
        }
    }

    private fun isBiometricEnrolled(result: MethodChannel.Result) {
        try {
            val fingerprintManager = FingerprintManagerCompat.from(activity!!)
            val isEnrolled =
                fingerprintManager.isHardwareDetected && fingerprintManager.hasEnrolledFingerprints()
            result.success(isEnrolled)
        } catch (e: Exception) {
            result.error(errorCode, e.message, "${e.stackTrace}")
        }
    }

    /*
   * Starts authentication process
   */
    private fun authenticate(call: MethodCall, result: MethodChannel.Result) {
        if (authInProgress.get()) {
            result.error("auth_in_progress", "Authentication in progress", null)
            return
        }
        if (activity == null || activity!!.isFinishing) {
            result.error("no_activity", "local_auth plugin requires a foreground activity", null)
            return
        }
        if (activity !is FragmentActivity) {
            result.error(
                "no_fragment_activity",
                "local_auth plugin requires activity to be a FragmentActivity.",
                null
            )
            return
        }
        if (!isDeviceSupportedFlag) {
            authInProgress.set(false)
            result.error("NotAvailable", "Required security features not enabled", null)
            return
        }
        authInProgress.set(true)
        val completionHandler = createAuthCompletionHandler(result)
        val isBiometricOnly = call.argument<Boolean>("biometricOnly")!!
        val allowCredentials = !isBiometricOnly && canAuthenticateWithDeviceCredential()
        sendAuthenticationRequest(call, completionHandler, allowCredentials)
        return
    }

    private fun createAuthCompletionHandler(result: MethodChannel.Result): AuthCompletionHandler {
        return object : AuthCompletionHandler {

            override fun  onSuccess() {
                authenticateSuccess(result)
            }

            override fun onFailure() {
                authenticateFail(result)
            }

            override fun onError(code: String?, error: String?) {
                if (authInProgress.compareAndSet(true, false)) {
                    result.error(code!!, error, null)
                }
            }
        }
    }

    private fun sendAuthenticationRequest(
        call: MethodCall?, completionHandler: AuthCompletionHandler, allowCredentials: Boolean
    ) {
        authHelper = AuthenticationHelper(
            lifecycle,
            (activity as FragmentActivity?)!!,
            call!!, completionHandler, allowCredentials
        )
        authHelper!!.authenticate()
    }

    private fun authenticateSuccess(result: MethodChannel.Result) {
        if (authInProgress.compareAndSet(true, false)) {
            result.success(true)
        }
    }

    private fun authenticateFail(result: MethodChannel.Result?) {
        if (authInProgress.compareAndSet(true, false)) {
            result!!.success(false)
        }
    }

    /*
   * Stops the authentication if in progress.
   */
    private fun stopAuthentication(result: MethodChannel.Result) {
        try {
            if (authHelper != null && authInProgress.get()) {
                authHelper!!.stopAuthentication()
                authHelper = null
            }
            authInProgress.set(false)
            result.success(true)
        } catch (e: Exception) {
            result.success(false)
        }
    }

    private fun deviceSupportsBiometrics(result: MethodChannel.Result) {
        result.success(hasBiometricHardware())
    }

    /*
   * Returns enrolled biometric types available on device.
   */
    private fun getEnrolledBiometrics(result: MethodChannel.Result) {
        try {
            if (activity == null || activity!!.isFinishing) {
                result.error(
                    "no_activity",
                    "local_auth plugin requires a foreground activity",
                    null
                )
                return
            }
            val biometrics = getAvailableBiometrics()
            result.success(biometrics)
        } catch (e: Exception) {
            result.error("no_biometrics_available", e.message, null)
        }
    }

    private fun getAvailableBiometrics(): ArrayList<String> {
        val biometrics = ArrayList<String>()
        if (activity == null || activity!!.isFinishing) {
            return biometrics
        }
        val packageManager = activity!!.packageManager
        if (Build.VERSION.SDK_INT >= 23) {
            if (packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
                biometrics.add("fingerprint")
            }
        }
        if (Build.VERSION.SDK_INT >= 29) {
            if (packageManager.hasSystemFeature(PackageManager.FEATURE_FACE)) {
                biometrics.add("face")
            }
            if (packageManager.hasSystemFeature(PackageManager.FEATURE_IRIS)) {
                biometrics.add("iris")
            }
        }
        return biometrics
    }

    private val isDeviceSecure: Boolean
        get() = if (keyguardManager == null) false else Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && keyguardManager!!.isDeviceSecure

    private val isDeviceSupportedFlag: Boolean
        get() = isDeviceSecure || canAuthenticateWithBiometrics()

    private fun canAuthenticateWithBiometrics(): Boolean {
        return if (biometricManager == null) false else (biometricManager!!.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_WEAK
        )
                == BiometricManager.BIOMETRIC_SUCCESS)
    }

    private fun hasBiometricHardware(): Boolean {
        return if (biometricManager == null) false else (biometricManager!!.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_WEAK
        )
                != BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE)
    }

    private fun canAuthenticateWithDeviceCredential(): Boolean {
        if (Build.VERSION.SDK_INT < 30) {
            // Checking for device credential only authentication via the BiometricManager
            // is not allowed before API level 30, so we check for presence of PIN, pattern,
            // or password instead.
            return isDeviceSecure
        }
        return if (biometricManager == null) false else (biometricManager!!.canAuthenticate(
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
                == BiometricManager.BIOMETRIC_SUCCESS)
    }

    private fun isDeviceSupportedMethod(result: MethodChannel.Result) {
        result.success(isDeviceSupportedFlag)
    }

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, CHANNEL_NAME)
        channel!!.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPluginBinding) {}
    private fun setServicesFromActivity(activity: Activity?) {
        if (activity == null) return
        this.activity = activity
        val context = activity.baseContext
        biometricManager = BiometricManager.from(activity)
        keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
        binding.addActivityResultListener(resultListener)
        setServicesFromActivity(activity)
        lifecycle = FlutterLifecycleAdapter.getActivityLifecycle(binding)
        channel!!.setMethodCallHandler(this)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        lifecycle = null
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
        binding.addActivityResultListener(resultListener)
        setServicesFromActivity(activity)
        lifecycle = FlutterLifecycleAdapter.getActivityLifecycle(binding)
    }

    override fun onDetachedFromActivity() {
        lifecycle = null
        channel!!.setMethodCallHandler(null)
        activity = null
    }

    fun setBiometricManager(biometricManager: BiometricManager?) {
        this.biometricManager = biometricManager
    }

    fun setKeyguardManager(keyguardManager: KeyguardManager?) {
        this.keyguardManager = keyguardManager
    }

    companion object {
        private const val CHANNEL_NAME = "biometric"
        private const val LOCK_REQUEST_CODE = 221
        private const val errorCode = "driven-biometric"
        private const val authenticate = "authenticate"
        private const val getAvailableBiometrics = "getAvailableBiometrics"
        private const val isDeviceSupported = "isDeviceSupported"
        private const val stopAuthentication = "stopAuthentication"
        private const val deviceSupportsBiometrics = "deviceSupportsBiometrics"
        private const val checkDeviceBiometricStatus = "checkDeviceBiometricStatus"
    }
}