package com.fleetcor.biometric

import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.app.Application
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.ContextThemeWrapper
import android.view.LayoutInflater
import android.view.View
import android.widget.TextView
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.PromptInfo
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import com.fab.biometric.R
import io.flutter.plugin.common.MethodCall
import java.util.concurrent.Executor

internal class AuthenticationHelper(
    private val lifecycle: Lifecycle?,
    private val activity: FragmentActivity,
    private val call: MethodCall,
    private val completionHandler: AuthCompletionHandler,
    allowCredentials: Boolean
) : BiometricPrompt.AuthenticationCallback(),
    Application.ActivityLifecycleCallbacks, DefaultLifecycleObserver {
    internal interface AuthCompletionHandler {
        fun onSuccess()
        fun onFailure()

        /**
         * @param code The error code to be returned to Flutter app.
         * @param error The description of the error.
         */
        fun onError(code: String?, error: String?)
    }

    private val promptInfo: PromptInfo
    private val isAuthSticky: Boolean
    private val uiThreadExecutor: UiThreadExecutor
    private var activityPaused = false
    private var biometricPrompt: BiometricPrompt? = null

    init {
        isAuthSticky = call.argument("stickyAuth")!!
        uiThreadExecutor = UiThreadExecutor()
        val promptBuilder = PromptInfo.Builder()
            .setDescription(call.argument<Any>("localizedReason") as String?)
            .setTitle((call.argument<Any>("signInTitle") as String?)!!)
            .setSubtitle(call.argument<Any>("biometricHint") as String?)
            .setConfirmationRequired((call.argument<Any>("sensitiveTransaction") as Boolean?)!!)
            .setConfirmationRequired((call.argument<Any>("sensitiveTransaction") as Boolean?)!!)
        var allowedAuthenticators = (BiometricManager.Authenticators.BIOMETRIC_WEAK
                or BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (allowCredentials) {
            allowedAuthenticators =
                allowedAuthenticators or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            promptBuilder.setNegativeButtonText((call.argument<Any>("cancelButton") as String?)!!)
        }
        promptBuilder.setAllowedAuthenticators(allowedAuthenticators)
        promptInfo = promptBuilder.build()
    }

    /** Start the biometric listener.  */
    fun authenticate() {
        if (lifecycle != null) {
            lifecycle.addObserver(this)
        } else {
            activity.application.registerActivityLifecycleCallbacks(this)
        }
        biometricPrompt = BiometricPrompt(activity, uiThreadExecutor, this)
        biometricPrompt!!.authenticate(promptInfo)
    }

    /** Cancels the biometric authentication.  */
    fun stopAuthentication() {
        if (biometricPrompt != null) {
            biometricPrompt!!.cancelAuthentication()
            biometricPrompt = null
        }
    }

    /** Stops the biometric listener.  */
    private fun stop() {
        if (lifecycle != null) {
            lifecycle.removeObserver(this)
            return
        }
        activity.application.unregisterActivityLifecycleCallbacks(this)
    }

    @SuppressLint("SwitchIntDef")
    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        when (errorCode) {
            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> {
                if (call.argument("useErrorDialogs")!!) {
                    showGoToSettingsDialog(
                        call.argument<Any>("deviceCredentialsRequired") as String?,
                        call.argument<Any>("deviceCredentialsSetupDescription") as String?
                    )
                    return
                }
                completionHandler.onError("NotAvailable", "Security credentials not available.")
            }
            BiometricPrompt.ERROR_NO_SPACE, BiometricPrompt.ERROR_NO_BIOMETRICS -> {
                if (call.argument("useErrorDialogs")!!) {
                    showGoToSettingsDialog(
                        call.argument<Any>("biometricRequired") as String?,
                        call.argument<Any>("goToSettingDescription") as String?
                    )
                    return
                }
                completionHandler.onError("NotEnrolled", "No Biometrics enrolled on this device.")
            }
            BiometricPrompt.ERROR_HW_UNAVAILABLE, BiometricPrompt.ERROR_HW_NOT_PRESENT -> completionHandler.onError(
                "NotAvailable",
                "Security credentials not available."
            )
            BiometricPrompt.ERROR_LOCKOUT -> completionHandler.onError(
                "LockedOut",
                "The operation was canceled because the API is locked out due to too many attempts. This occurs after 5 failed attempts, and lasts for 30 seconds."
            )
            BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> completionHandler.onError(
                "PermanentlyLockedOut",
                "The operation was canceled because ERROR_LOCKOUT occurred too many times. Biometric authentication is disabled until the user unlocks with strong authentication (PIN/Pattern/Password)"
            )
            BiometricPrompt.ERROR_CANCELED ->         // If we are doing sticky auth and the activity has been paused,
                // ignore this error. We will start listening again when resumed.
                if (activityPaused && isAuthSticky) {
                    return
                } else {
                    completionHandler.onFailure()
                }
            else -> completionHandler.onFailure()
        }
        stop()
    }

    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        completionHandler.onSuccess()
        stop()
    }

    override fun onAuthenticationFailed() {}

    override fun onActivityPaused(ignored: Activity) {
        if (isAuthSticky) {
            activityPaused = true
        }
    }

    override fun onActivityResumed(ignored: Activity) {
        if (isAuthSticky) {
            activityPaused = false
            val prompt = BiometricPrompt(
                activity, uiThreadExecutor, this
            )
            uiThreadExecutor.handler.post { prompt.authenticate(promptInfo) }
        }
    }

    override fun onPause(owner: LifecycleOwner) {
        onActivityPaused(activity)
    }

    override fun onResume(owner: LifecycleOwner) {
        onActivityResumed(activity)
    }

    // Suppress inflateParams lint because dialogs do not need to attach to a parent view.
    @SuppressLint("InflateParams")
    private fun showGoToSettingsDialog(title: String?, descriptionText: String?) {
        val view: View = LayoutInflater.from(activity).inflate(R.layout.go_to_setting, null, false)
        val message = view.findViewById<View>(R.id.fingerprint_required) as TextView
        val description = view.findViewById<View>(R.id.go_to_setting_description) as TextView
        message.text = title
        description.text = descriptionText
        val context: Context = ContextThemeWrapper(activity, R.style.AlertDialogCustom)
        val goToSettingHandler =
            DialogInterface.OnClickListener { dialog, which ->
                completionHandler.onFailure()
                stop()
                activity.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
            }
        val cancelHandler =
            DialogInterface.OnClickListener { dialog, which ->
                completionHandler.onFailure()
                stop()
            }
        AlertDialog.Builder(context)
            .setView(view)
            .setPositiveButton(call.argument<Any>("goToSetting") as String?, goToSettingHandler)
            .setNegativeButton(call.argument<Any>("cancelButton") as String?, cancelHandler)
            .setCancelable(false)
            .show()
    }

    // Unused methods for activity lifecycle.
    override fun onActivityCreated(activity: Activity, bundle: Bundle?) {}
    override fun onActivityStarted(activity: Activity) {}
    override fun onActivityStopped(activity: Activity) {}
    override fun onActivitySaveInstanceState(activity: Activity, bundle: Bundle) {}
    override fun onActivityDestroyed(activity: Activity) {}
    override fun onDestroy(owner: LifecycleOwner) {}
    override fun onStop(owner: LifecycleOwner) {}
    override fun onStart(owner: LifecycleOwner) {}
    override fun onCreate(owner: LifecycleOwner) {}
    private class UiThreadExecutor : Executor {
        val handler = Handler(Looper.getMainLooper())
        override fun execute(command: Runnable) {
            handler.post(command)
        }
    }
}