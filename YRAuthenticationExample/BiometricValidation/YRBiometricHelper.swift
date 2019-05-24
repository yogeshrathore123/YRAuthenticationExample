//
//  YRBiometricHelper.swift
//  YRAuthentication
//
//  Created by Yogesh Rathore on 23/05/19.
//  Copyright © 2019 Yogesh Rathore. All rights reserved.
//

import Foundation
import UIKit
import LocalAuthentication

public enum BiometricAuthenticationStatus: Int {
    case Success
    case Failure
    case SessionCancelled
    case TryAgain
    case PasswordOptionSelected
    case BiometryNotEnrolled
    case PasscodeNotSet
    case BiometryNotAvailable
    case UnknownError
}

public enum AuthenticationPolicy: Int {
    case deviceOwnerAuthWithBiometrics
    case deviceOwnerAuth
}

public typealias BiometricAuthenticationCompletion = (_ status:BiometricAuthenticationStatus,_ title: String,_ message: String) -> Void
public var authenticationPolicy: LAPolicy = LAPolicy.deviceOwnerAuthenticationWithBiometrics

public class YRBiometricHelper {
    
    public init() {
    }
    
    func setAuthenticationPolicy(policy: AuthenticationPolicy) {
        switch policy {
        case .deviceOwnerAuth:
            authenticationPolicy = LAPolicy.deviceOwnerAuthentication
        case .deviceOwnerAuthWithBiometrics:
            authenticationPolicy = LAPolicy.deviceOwnerAuthenticationWithBiometrics
        }
    }
    
    /// Function to authenticate user
    ///
    /// - Parameters:
    ///   - policy: AuthenticationPolicy
    ///   - completion: completion of type 'BiometricAuthenticationCompletion'
    public func authenticateUser(policy: AuthenticationPolicy, completion: @escaping BiometricAuthenticationCompletion) {
        let context = LAContext()
        var error: NSError?
        setAuthenticationPolicy(policy: policy)
        if policy == .deviceOwnerAuthWithBiometrics {
            context.localizedFallbackTitle = ""
        }
        if context.canEvaluatePolicy(
            authenticationPolicy,
            error: &error) {
            // Device can use biometric authentication
            context.evaluatePolicy(
                authenticationPolicy,
                localizedReason: "Access requires authentication",
                reply: {(success, error) in
                    DispatchQueue.main.async {
                        if let err = error {
                            switch err._code {
                            case LAError.Code.systemCancel.rawValue:
                                completion(BiometricAuthenticationStatus.SessionCancelled, "Session Cancelled", err.localizedDescription)
                            case LAError.Code.userCancel.rawValue:
                                completion(BiometricAuthenticationStatus.TryAgain, "Please try again", err.localizedDescription)
                            case LAError.Code.userFallback.rawValue:
                                completion(BiometricAuthenticationStatus.PasswordOptionSelected, "Authentication", "Password option selected")
                            default:
                                completion(BiometricAuthenticationStatus.Failure, "Authentication failed", err.localizedDescription)
                            }
                        } else {
                            completion(BiometricAuthenticationStatus.Success, "Authentication Successful", "You now have full access")
                        }
                    }
            })
        } else {
            // Device cannot use biometric authentication
            if let err = error {
                if #available(iOS 11.0, *) {
                    switch err.code {
                    case LAError.Code.biometryNotEnrolled.rawValue:
                        completion(BiometricAuthenticationStatus.BiometryNotEnrolled, "User is not enrolled", err.localizedDescription)
                    case LAError.Code.passcodeNotSet.rawValue:
                        completion(BiometricAuthenticationStatus.PasscodeNotSet, "A passcode has not been set", err.localizedDescription)
                    case LAError.Code.biometryNotAvailable.rawValue:
                        completion(BiometricAuthenticationStatus.BiometryNotAvailable, "Biometric authentication not available", err.localizedDescription)
                    default:
                        completion(BiometricAuthenticationStatus.UnknownError, "Unknown error", err.localizedDescription)
                    }
                } else {
                    // Fallback on earlier versions
                    completion(BiometricAuthenticationStatus.UnknownError, "Unknown error", err.localizedDescription)
                }
            }
        }
    }
}
