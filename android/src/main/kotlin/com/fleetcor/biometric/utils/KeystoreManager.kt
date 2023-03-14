package com.fleetcor.biometric.utils

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.lang.Byte
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec


class KeystoreManager(ctx: Context, crypto: CryptoHelper) {
    
    private var applicationContext : Context? = null
    private var cryptoHelper : CryptoHelper

    init {
        applicationContext = ctx
        cryptoHelper = crypto
    }

    fun generateMasterKeys(){
        val ks = KeyStore.getInstance(KEYSTORE)
        ks.load(null)
        if (!ks.containsAlias(MASTER_KEY_ALIAS))
            generateSymmetricKey()
        if (!ks.containsAlias(MASTER_ASYM_KEY_ALIAS))
            generateAsymmetricKeys()
    }

    private fun generateAsymmetricKeys(){
        val keyGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, KEYSTORE
        )

        val builder = KeyGenParameterSpec.Builder(MASTER_ASYM_KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
                .setDigests(
                        KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512
                )
                .setAlgorithmParameterSpec(ECGenParameterSpec(SECP256R1))
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(-1)

        keyGenerator.initialize(builder.build())
        keyGenerator.generateKeyPair()
    }

    private fun generateSymmetricKey(){
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(MASTER_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_SIZE)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(-1)
        keyGenerator.init(builder.build())
        keyGenerator.generateKey()
    }

    fun getLocalEncryptionCipher():Cipher {
        val ks = KeyStore.getInstance(KEYSTORE)
        ks.load(null)
        val key = ks.getKey(MASTER_KEY_ALIAS, null)
        val cipher = Cipher.getInstance(AES_GCM_NOPADDING)
        val preferences = applicationContext?.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
        var iv : ByteArray
        if (preferences!!.contains(KEYSTORE_IV_NAME)){
            iv = cryptoHelper.hexToByteArray(preferences.getString(KEYSTORE_IV_NAME, "")!!)
            val spec = GCMParameterSpec(IV_SIZE * Byte.SIZE, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key, cipher.parameters)
            val editor = preferences.edit()
            editor?.putString(KEYSTORE_IV_NAME, cryptoHelper.byteArrayToHex(cipher.iv))
            editor?.apply()
        }

        return cipher
    }

    fun encryptApplicationKey(pt: ByteArray, cipher: Cipher): ByteArray {
        return cipher.doFinal(pt)?: throw IllegalArgumentException("ENCRYPTION ERROR!")
    }

    fun decryptApplicationKey(ct: ByteArray, cipher: Cipher): ByteArray {
        return cipher.doFinal(ct)?: throw IllegalArgumentException("DECRYPTION ERROR!")
    }

    fun getSignature(): Signature {
        val ks = KeyStore.getInstance(KEYSTORE)
        ks.load(null)
        val key = ks.getKey(MASTER_ASYM_KEY_ALIAS, null) as PrivateKey
        val signature = Signature.getInstance(SHA512ECDSA)
        signature.initSign(key)
        return signature
    }

    fun verifySignature(dataSigned: ByteArray, data: ByteArray): Boolean {
        val ks = KeyStore.getInstance(KEYSTORE)
        ks.load(null)
        val certificate = ks.getCertificate(MASTER_ASYM_KEY_ALIAS)
        val signature = Signature.getInstance(SHA512ECDSA)
        signature.initVerify(certificate)
        signature.update(data)
        return signature.verify(dataSigned)
    }

    fun removeKey(){
        val ks = KeyStore.getInstance(KEYSTORE)
        ks.load(null)
        ks.deleteEntry(MASTER_KEY_ALIAS)
        ks.deleteEntry(MASTER_ASYM_KEY_ALIAS)
        generateMasterKeys()
    }
    
    companion object {
        const val IV_SIZE = 16
        const val KEY_SIZE = 256
        const val MASTER_KEY_ALIAS = "SYMMETRIC_MASTER_KEY"
        const val MASTER_ASYM_KEY_ALIAS = "ASYMMETRIC_MASTER_KEY"
        const val SHARED_PREFERENCES_NAME = "KeyStoreSettings"
        const val KEYSTORE_IV_NAME = "KeyStoreIV"
        const val KEYSTORE = "AndroidKeyStore"
        const val SHA512ECDSA = "SHA512withECDSA"
        const val AES_GCM_NOPADDING = "AES/GCM/NoPadding"
        const val SECP256R1 = "secp256r1"
    }
}