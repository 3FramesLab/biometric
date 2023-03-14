package com.fleetcor.biometric.utils

import javax.crypto.Cipher
import android.content.Context.MODE_PRIVATE
import android.content.Context
import java.security.Signature


class SecureLocalManager(ctx: Context) {
    companion object {
        const val SHARED_PREFERENCES_NAME = "corp_settings"
        const val APPLICATION_KEY_NAME = "corp_ApplicationKey"
        const val SECRET_TEXT_NAME = "corp_Secret"
        const val IV_SIZE = 16
    }

    private var keystoreManager: KeystoreManager
    private var cryptoHelper: CryptoHelper
    private lateinit var applicationKey : ByteArray
    private var applicationContext : Context? = null

    init {
        applicationContext = ctx
        cryptoHelper = CryptoHelper()
        keystoreManager = KeystoreManager(applicationContext!!, cryptoHelper)
        keystoreManager.generateMasterKeys()
    }


    fun encryptLocalData(data: ByteArray):ByteArray {
        val iv = cryptoHelper.generateIV(IV_SIZE)
        return iv + cryptoHelper.encryptData(data, applicationKey, iv)
    }

    fun decryptLocalData(data: ByteArray):ByteArray {
        val iv = data.sliceArray(0 .. IV_SIZE-1)
        val ct = data.sliceArray(IV_SIZE.. data.lastIndex)
        return cryptoHelper.decryptData(ct, applicationKey, iv)
    }

    fun getLocalEncryptionCipher():Cipher{
        return keystoreManager.getLocalEncryptionCipher()
    }

    fun resetMasterKey(){
        keystoreManager.removeKey()
        val preferences = applicationContext?.getSharedPreferences(SHARED_PREFERENCES_NAME, MODE_PRIVATE)
        preferences?.edit()?.remove(APPLICATION_KEY_NAME)?.apply()
    }

    fun loadOrGenerateApplicationKey(cipher: Cipher){
        val preferences = applicationContext?.getSharedPreferences(SHARED_PREFERENCES_NAME, MODE_PRIVATE)
        if (preferences!!.contains(APPLICATION_KEY_NAME)) {
            val encryptedAppKey = preferences.getString(APPLICATION_KEY_NAME, "")
            applicationKey = keystoreManager.decryptApplicationKey(cryptoHelper.hexToByteArray(encryptedAppKey!!), cipher)
        }
        else{
            applicationKey = cryptoHelper.generateApplicationKey()
            val editor = preferences.edit()
            val encryptedAppKey = cryptoHelper.byteArrayToHex(keystoreManager.encryptApplicationKey(applicationKey, cipher))
            editor?.putString(APPLICATION_KEY_NAME, encryptedAppKey)
            editor?.apply()
        }
    }

    fun getSignature(): Signature {
        return keystoreManager.getSignature()
    }

    fun signData(data: ByteArray, signature: Signature): ByteArray {
        signature.update(data)
        return signature.sign()
    }

    fun verifyDataSignature(dataSigned: ByteArray, data: ByteArray): Boolean {
        return keystoreManager.verifySignature(dataSigned, data)
    }
}