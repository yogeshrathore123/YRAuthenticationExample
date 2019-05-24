//
//  YRSymmetricCryptor.swift
//  YRAuthentication
//
//  Created by Yogesh Rathore on 23/05/19.
//  Copyright © 2019 Yogesh Rathore. All rights reserved.
//

import Foundation
import CommonCrypto

protocol Randomizer {
    static func randomIv() -> Data
    static func randomSalt() -> Data
    static func randomData(length: Int) -> Data
}

protocol Crypter {
    func encrypt(_ digest: Data) throws -> Data
    func decrypt(_ encrypted: Data) throws -> Data
}

struct AES256Crypter {
    
    private var key: Data
    private var iv: Data
    
    public init(key: Data, iv: Data) throws {
        guard key.count == kCCKeySizeAES256 else {
            throw Error.badKeyLength
        }
        guard iv.count == kCCBlockSizeAES128 else {
            throw Error.badInputVectorLength
        }
        self.key = key
        self.iv = iv
    }
    
    enum Error: Swift.Error {
        case keyGeneration(status: Int)
        case cryptoFailed(status: CCCryptorStatus)
        case badKeyLength
        case badInputVectorLength
    }
    
    
    /// Function to encrypt or decrypt data
    ///
    /// - Parameters:
    ///   - input: input data to be encrypted/decrypted
    ///   - operation: encryption/decryption operation
    /// - Returns: result data
    /// - Throws: throws errors
    private func crypt(input: Data, operation: CCOperation) throws -> Data {
        var outLength = Int(0)
        var outBytes = [UInt8](repeating: 0, count: input.count + kCCBlockSizeAES128)
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)
        input.withUnsafeBytes { (encryptedBytes: UnsafePointer<UInt8>!) -> () in
            iv.withUnsafeBytes { (ivBytes: UnsafePointer<UInt8>!) in
                key.withUnsafeBytes { (keyBytes: UnsafePointer<UInt8>!) -> () in
                    status = CCCrypt(operation,
                                     CCAlgorithm(kCCAlgorithmAES128),            // algorithm
                        CCOptions(kCCOptionPKCS7Padding),           // options
                        keyBytes,                                   // key
                        key.count,                                  // keylength
                        ivBytes,                                    // iv
                        encryptedBytes,                             // dataIn
                        input.count,                                // dataInLength
                        &outBytes,                                  // dataOut
                        outBytes.count,                             // dataOutAvailable
                        &outLength)                                 // dataOutMoved
                }
            }
        }
        guard status == kCCSuccess else {
            throw Error.cryptoFailed(status: status)
        }
        return Data(bytes: UnsafePointer<UInt8>(outBytes), count: outLength)
    }
    
    
    /// Function to create key using salt
    ///
    /// - Parameters:
    ///   - password: an input password data
    ///   - salt: salt
    /// - Returns: resultant key created
    /// - Throws: throws errors
    static func createKey(password: Data, salt: Data) throws -> Data {
        let length = kCCKeySizeAES256
        var status = Int32(0)
        var derivedBytes = [UInt8](repeating: 0, count: length)
        password.withUnsafeBytes { (passwordBytes: UnsafePointer<Int8>!) in
            salt.withUnsafeBytes { (saltBytes: UnsafePointer<UInt8>!) in
                status = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),                  // algorithm
                    passwordBytes,                                // password
                    password.count,                               // passwordLen
                    saltBytes,                                    // salt
                    salt.count,                                   // saltLen
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),   // prf
                    10000,                                        // rounds
                    &derivedBytes,                                // derivedKey
                    length)                                       // derivedKeyLen
            }
        }
        guard status == 0 else {
            throw Error.keyGeneration(status: Int(status))
        }
        return Data(bytes: UnsafePointer<UInt8>(derivedBytes), count: length)
    }
    
}


extension AES256Crypter: Crypter {
    
    func encrypt(_ digest: Data) throws -> Data {
        return try crypt(input: digest, operation: CCOperation(kCCEncrypt))
    }
    
    func decrypt(_ encrypted: Data) throws -> Data {
        return try crypt(input: encrypted, operation: CCOperation(kCCDecrypt))
    }
    
}

extension AES256Crypter: Randomizer {
    
    /// Function to generate random IV
    ///
    /// - Returns: RandomData of length kCCBlockSizeAES128
    static func randomIv() -> Data {
        return randomData(length: kCCBlockSizeAES128)
    }
    
    /// Function to generate random Salt
    ///
    /// - Returns: RandomData of length 8
    static func randomSalt() -> Data {
        return randomData(length: 8)
    }
    
    
    /// Function to generate random Password
    ///
    /// - Returns: RandomData of length 32
    static func randomPassword() -> String {
        return randomString(length: 32)
    }
    
    
    /// Function to generate random data of of length: length
    ///
    /// - Parameter length: length of random data required
    /// - Returns: Random data of length: length
    static func randomData(length: Int) -> Data {
        var data = Data(count: length)
        let status = data.withUnsafeMutableBytes { mutableBytes in
            SecRandomCopyBytes(kSecRandomDefault, length, mutableBytes)
        }
        assert(status == Int32(0))
        return data
    }
    
    
    /// Function to generate random String of length:length
    ///
    /// - Parameter length: length of random string required
    /// - Returns: Random String of length: length
    static func randomString(length: Int) -> String {
        let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return String((0...length-1).map{ _ in letters.randomElement()! })
    }
}

public class YRSymmetricCryptor {
    
    let AES_ENCRYPTOR_KEY = "AES_ENCRYPTOR_KEY"
    let AES_ENCRYPTOR_IV = "AES_ENCRYPTOR_IV"
    
    public init() {
    }
    
    
    /// Function to get Key, IV, and call encrypt method
    ///
    /// - Parameter text: input text to be encrypted
    /// - Returns: Encrypted text
    public func encryptData(text: String) -> String? {
        var aes: AES256Crypter?
        do {
            // If key and iv present in Keychain, create AES256Crypter object
            if let key = KeychainWrapper.standard.data(forKey: AES_ENCRYPTOR_KEY) {
                let iv = KeychainWrapper.standard.data(forKey: AES_ENCRYPTOR_IV)
                aes = try AES256Crypter(key: key, iv: iv!)
            } else {
                // If key and iv not present in Keychain, create them, store to keychain and then create AES256Crypter object
                let password = AES256Crypter.randomPassword()
                let salt = AES256Crypter.randomSalt()
                let iv = AES256Crypter.randomIv()
                let key = try AES256Crypter.createKey(password: password.data(using: .utf8)!, salt: salt)
                KeychainWrapper.standard.set(key, forKey: AES_ENCRYPTOR_KEY)
                KeychainWrapper.standard.set(iv, forKey: AES_ENCRYPTOR_IV)
                aes = try AES256Crypter(key: key, iv: iv)
            }
            if let sourceData = text.data(using: .utf8) {
                let encryptedData = try aes!.encrypt(sourceData)
                return encryptedData.base64EncodedString()
            }
        } catch {
            print("Failed")
            print(error)
        }
        return ""
    }
    
    
    /// Function to get Key, IV and call decrypt method
    ///
    /// - Parameter encryptedString: Encrypted text to be decrypted
    /// - Returns: Decrypted plain text
    public func decryptData(encryptedString: String) -> String {
        let key: Data? = KeychainWrapper.standard.data(forKey: AES_ENCRYPTOR_KEY)
        let iv: Data? = KeychainWrapper.standard.data(forKey: AES_ENCRYPTOR_IV)
        do {
            let aes = try AES256Crypter(key: key!, iv: iv!)
            let decryptedData = try aes.decrypt(Data(base64Encoded: encryptedString)!)
            return String(data: decryptedData, encoding: .utf8)!
        } catch {
            print("Failed")
            print(error)
        }
        return ""
    }
}

