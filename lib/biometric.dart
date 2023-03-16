import 'dart:async';

import 'package:biometric/dialog_messages.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:platform/platform.dart';

import 'auth_strings.dart';
import 'error_codes.dart';

enum BiometricType { face, fingerprint, iris, weak, strong }

enum DeviceBiometricStatus {
  permissionNotGranted(permissionNotGrantedStatus),
  permissionGranted(permissionGrantedStatus),
  biometricNotEnrolled(biometricNotEnrolledStatus),
  otherException(otherExceptionStatus);

  const DeviceBiometricStatus(this.status);
  final String status;
}

class Biometric {
  static const MethodChannel _channel = const MethodChannel('biometric');
  static const _isBiometricEnrolled = 'checkDeviceBiometricStatus';

  Platform _platform = const LocalPlatform();

  Future<String> get platformVersion async {
    final String version = await _channel.invokeMethod('getPlatformVersion');
    return version;
  }

  /// Creates SHA256 RSA key pair for signing using biometrics
  ///
  /// Will create a new keypair each time method is called
  ///
  /// Returns Base-64 encoded public key as a [String] if successful
  ///
  /// [reason] is the message to show when user will be prompted to authenticate using biometrics
  ///
  /// [showIOSErrorDialog] is used on iOS side to decide if error dialog should be displayed
  ///
  /// Provide [dialogMessages] if you want to customize messages for the auth dialog
  Future<dynamic> createKeys({
    showIOSErrorDialog = true,
    DialogMessages dialogMessages = const DialogMessages(),
    @required String? localizedReason,
    bool useErrorDialogs = true,
    AndroidAuthMessages androidAuthStrings = const AndroidAuthMessages(),
    bool sensitiveTransaction = true,
    bool biometricOnly = false,
    bool stickyAuth = false,
  }) async {
    assert(localizedReason != null);
    final Map<String, Object?> args = <String, Object?>{
      'reason': localizedReason,
      'useErrorDialogs': showIOSErrorDialog,
      'localizedReason': localizedReason,
      'stickyAuth': stickyAuth,
      'sensitiveTransaction': sensitiveTransaction,
      'biometricOnly': biometricOnly,
    };
    args.addAll(androidAuthStrings.args);

    return await _channel.invokeMethod<dynamic>('createKeys', args);
  }

  /// Signs [payload] using generated private key. [createKeys()] should be called once before using this method.
  ///
  /// Returns Base-64 encoded signature as a [String] if successful
  ///
  /// [payload] is Base 64 encoded string you want to sign using SHA256
  ///
  /// [reason] is the message to show when user will be prompted to authenticate using biometrics
  ///
  /// [showIOSErrorDialog] is used on iOS side to decide if error dialog should be displayed
  ///
  /// Provide [dialogMessages] if you want to customize messages for the auth dialog
  Future<dynamic> sign({
    @required String? payload,
    @required String? reason,
    showIOSErrorDialog = true,
    DialogMessages dialogMessages = const DialogMessages(),
  }) async {
    assert(payload != null);
    assert(reason != null);
    final Map<String, Object?> args = <String, Object?>{
      'payload': payload,
      'reason': reason,
      'useErrorDialogs': showIOSErrorDialog,
    };

    args.addAll(dialogMessages.messages);

    return await _channel.invokeMethod<dynamic>('sign', args);
  }

  /// The `authenticateWithBiometrics` method has been deprecated.
  /// Use `authenticate` with `biometricOnly: true` instead
  @Deprecated("Use `authenticate` with `biometricOnly: true` instead")
  Future<bool> authenticateWithBiometrics({
    @required String? localizedReason,
    bool useErrorDialogs = true,
    bool stickyAuth = false,
    AndroidAuthMessages androidAuthStrings = const AndroidAuthMessages(),
    IOSAuthMessages iOSAuthStrings = const IOSAuthMessages(),
    bool sensitiveTransaction = true,
  }) =>
      authenticate(
        localizedReason: localizedReason,
        useErrorDialogs: useErrorDialogs,
        stickyAuth: stickyAuth,
        androidAuthStrings: androidAuthStrings,
        iOSAuthStrings: iOSAuthStrings,
        sensitiveTransaction: sensitiveTransaction,
        biometricOnly: true,
      );

  Future<bool> authenticate({
    @required String? localizedReason,
    bool useErrorDialogs = true,
    bool stickyAuth = false,
    AndroidAuthMessages androidAuthStrings = const AndroidAuthMessages(),
    IOSAuthMessages iOSAuthStrings = const IOSAuthMessages(),
    bool sensitiveTransaction = true,
    bool biometricOnly = false,
  }) async {
    assert(localizedReason != null);
    final Map<String, Object?> args = <String, Object?>{
      'localizedReason': localizedReason,
      'useErrorDialogs': useErrorDialogs,
      'stickyAuth': stickyAuth,
      'sensitiveTransaction': sensitiveTransaction,
      'biometricOnly': biometricOnly,
    };
    if (_platform.isIOS) {
      args.addAll(iOSAuthStrings.args);
    } else if (_platform.isAndroid) {
      args.addAll(androidAuthStrings.args);
    } else {
      throw PlatformException(
        code: otherOperatingSystem,
        message: 'Local authentication does not support non-Android/iOS '
            'operating systems.',
        details: 'Your operating system is ${_platform.operatingSystem}',
      );
    }
    return (await _channel.invokeMethod<bool>('authenticate', args)) ?? false;
  }

  /// Returns true if auth was cancelled successfully.
  /// This api only works for Android.
  /// Returns false if there was some error or no auth in progress.
  ///
  /// Returns [Future] bool true or false:
  Future<bool> stopAuthentication() async {
    if (_platform.isAndroid) {
      return await _channel.invokeMethod<bool>('stopAuthentication') ?? false;
    }
    return true;
  }

  /// Returns true if device is capable of checking biometrics
  ///
  /// Returns a [Future] bool true or false:
  Future<bool> get canCheckBiometrics async =>
      (await _channel.invokeListMethod<String>('getAvailableBiometrics'))!
          .isNotEmpty;

  /// Returns true if device is capable of checking biometrics or is able to
  /// fail over to device credentials.
  ///
  /// Returns a [Future] bool true or false:
  Future<bool> isDeviceSupported() async =>
      (await _channel.invokeMethod<bool>('isDeviceSupported')) ?? false;

  /// Returns a list of enrolled biometrics
  ///
  /// Returns a [Future] List<BiometricType> with the following possibilities:
  /// - BiometricType.face
  /// - BiometricType.fingerprint
  /// - BiometricType.iris (not yet implemented)
  Future<List<BiometricType>> getAvailableBiometrics() async {
    final List<String> result = (await _channel.invokeListMethod<String>(
          'getAvailableBiometrics',
        )) ??
        [];
    final List<BiometricType> biometrics = <BiometricType>[];
    result.forEach((String value) {
      switch (value) {
        case 'face':
          biometrics.add(BiometricType.face);
          break;
        case 'fingerprint':
          biometrics.add(BiometricType.fingerprint);
          break;
        case 'iris':
          biometrics.add(BiometricType.iris);
          break;
        case 'weak':
          biometrics.add(BiometricType.weak);
          break;
        case 'strong':
          biometrics.add(BiometricType.strong);
          break;
        case 'undefined':
          break;
      }
    });
    return biometrics;
  }

  Future<bool> get hasEnrolledBiometric async =>
      await deviceBiometricStatus() == DeviceBiometricStatus.permissionGranted;

  Future<DeviceBiometricStatus> deviceBiometricStatus() async {
    DeviceBiometricStatus biometricStatus =
        DeviceBiometricStatus.otherException;
    try {
      final bool result = await _channel.invokeMethod(_isBiometricEnrolled);
      if (result) {
        biometricStatus = DeviceBiometricStatus.permissionGranted;
      }
      return biometricStatus;
    } on PlatformException catch (error) {
      biometricStatus = _biometricStatusException(error);
    }
    return biometricStatus;
  }

  DeviceBiometricStatus _biometricStatusException(PlatformException error) {
    switch (error.message) {
      case permissionNotGrantedStatus:
        return DeviceBiometricStatus.permissionNotGranted;
      case biometricNotEnrolledStatus:
        return DeviceBiometricStatus.biometricNotEnrolled;
      default:
        return DeviceBiometricStatus.otherException;
    }
  }
}
