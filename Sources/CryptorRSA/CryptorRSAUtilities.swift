//
//  Utilities.swift
//  CryptorRSA
//
//  Created by Bill Abt on 1/17/17.
//
//  Copyright © 2017 IBM. All rights reserved.
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.
//

#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
	import CommonCrypto
#elseif os(Linux)
	import OpenSSL
#endif

import Foundation

// MARK: -- RSAUtilities

///
/// Various RSA Related Utility Functions
///
@available(macOS 10.12, iOS 10.0, *)
public extension CryptorRSA {
	
#if os(Linux)
	
	///
	/// Create a key from key data.
	///
	/// - Parameters:
	///		- keyData:			`Data` representation of the key.
	///		- type:				Type of key data.
	///
	///	- Returns:				`RSA` representation of the key.
	///
	static func createKey(from keyData: Data, type: CryptorRSA.RSAKey.KeyType) throws ->  NativeKey {
		
		let keyData = keyData
	
		// Create a memory BIO...
		let bio = BIO_new(BIO_s_mem())
	
        defer {
            BIO_free(bio)
        }
	
		// Create a BIO object with the key data...
		try keyData.withUnsafeBytes() { (buffer: UnsafePointer<UInt8>) in
			
			let len = BIO_write(bio, buffer, Int32(keyData.count))
            guard len != 0 else {
                let source = "Couldn't create BIO reference from key data"
                if let reason = CryptorRSA.getLastError(source: source) {
    
                    throw Error(code: ERR_ADD_KEY, reason: reason)
                }
                throw Error(code: ERR_ADD_KEY, reason: source + ": No OpenSSL error reported.")
            }
			// The below is equivalent of BIO_flush...
            BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, nil)
		}
		
		var evp_key: OpaquePointer?
	
        defer {
			EVP_PKEY_free(.make(optional: evp_key))
        }

        // Read in the key data and process depending on key type...
        if type == .publicType {
			
			evp_key = .init(PEM_read_bio_PUBKEY(bio, nil, nil, nil))

        } else {
			
			evp_key = .init(PEM_read_bio_PrivateKey(bio, nil, nil, nil))
        }

		let key = EVP_PKEY_get1_RSA(.make(optional: evp_key))
        if key == nil {
            let source = "Couldn't create key reference from key data"
            if let reason = CryptorRSA.getLastError(source: source) {
    
                throw Error(code: ERR_ADD_KEY, reason: reason)
            }
            throw Error(code: ERR_ADD_KEY, reason: source + ": No OpenSSL error reported.")
        }

		return .init(key!)
	}
	
	///
	/// Convert DER data to PEM data.
	///
	///	- Parameters:
	///		- derData:			`Data` in DER format.
	///		- type:				Type of key data.
	///
	///	- Returns:				PEM `Data` representation.
	///
	static func convertDerToPem(from derData: Data, type: CryptorRSA.RSAKey.KeyType) -> Data {
		
		// First convert the DER data to a base64 string...
		let base64String = derData.base64EncodedString()
	
		// Split the string into strings of length 65...
		let lines = base64String.split(to: 65)
		
		// Join those lines with a new line...
		let joinedLines = lines.joined(separator: "\n")
		
		// Add the appropriate header and footer depending on whether the key is public or private...
		if type == .publicType {
			
			return (CryptorRSA.PK_BEGIN_MARKER + "\n" + joinedLines + "\n" + CryptorRSA.PK_END_MARKER).data(using: .utf8)!
		
		} else {
			
			return (CryptorRSA.SK_BEGIN_MARKER + "\n" + joinedLines + "\n" + CryptorRSA.SK_END_MARKER).data(using: .utf8)!
		}
	}
	
	///
	/// Retrieve the OpenSSL error and text.
	///
	/// - Parameters:
	///		- source: 			The string describing the error.
	///
	///	- Returns:				`String` containing the error or `nil` if no error found.
	///
	static func getLastError(source: String) -> String? {
	
		var errorString: String

		let errorCode = Int32(ERR_get_error())
	
		if errorCode == 0 {
			return nil
		}

		if let errorStr = ERR_reason_error_string(UInt(errorCode)) {
			errorString = String(validatingUTF8: errorStr)!
		} else {
			errorString = "Could not determine error reason."
		}
		
		let reason = "ERROR: \(source), code: \(errorCode), reason: \(errorString)"
		return reason
	}
	
#else
	
	///
	/// Create a key from key data.
	///
	/// - Parameters:
	///		- keyData:			`Data` representation of the key.
	///		- type:				Type of key data.
	///
	///	- Returns:				`SecKey` representation of the key.
	///
	static func createKey(from keyData: Data, type: CryptorRSA.RSAKey.KeyType) throws ->  NativeKey {
		
		var keyData = keyData
        
		let keyClass = type == .publicType ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate
		
		let sizeInBits = keyData.count * MemoryLayout<UInt8>.size
		let keyDict: [CFString: Any] = [
			kSecAttrKeyType: kSecAttrKeyTypeRSA,
			kSecAttrKeyClass: keyClass,
			kSecAttrKeySizeInBits: NSNumber(value: sizeInBits)
		]
		
		guard let key = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, nil) else {
			
			throw Error(code: ERR_ADD_KEY, reason: "Couldn't create key reference from key data")
		}
        
		return key
		
	}
	
#endif

	///
	/// Get the Base64 representation of a PEM encoded string after stripping off the PEM markers.
	///
	/// - Parameters:
	///		- pemString:		`String` containing PEM formatted data.
	///
	/// - Returns:				Base64 encoded `String` containing the data.
	///
	static func base64String(for pemString: String) throws -> String {
		
		// Filter looking for new lines...
		var lines = pemString.components(separatedBy: "\n").filter { line in
			return !line.hasPrefix(CryptorRSA.GENERIC_BEGIN_MARKER) && !line.hasPrefix(CryptorRSA.GENERIC_END_MARKER)
		}
		
		// No lines, no data...
		guard lines.count != 0 else {
			throw Error(code: ERR_BASE64_PEM_DATA, reason: "Couldn't get data from PEM key: no data available after stripping headers.")
		}
		
		// Strip off any carriage returns...
		lines = lines.map { $0.replacingOccurrences(of: "\r", with: "") }
		
		return lines.joined(separator: "")
	}
	
	///
	/// This function strips the x509 from a provided ASN.1 DER public key. If the key doesn't contain a header,
	///	the DER data is returned as is.
	///
	/// - Parameters:
	///		- keyData:				`Data` containing the public key with or without the x509 header.
	///
	/// - Returns:					`Data` containing the public with header (if present) removed.
	///
	static func stripX509CertificateHeader(for keyData: Data) throws -> Data {
		
		let count = keyData.count / MemoryLayout<CUnsignedChar>.size
		
		guard count > 0 else {
			
			throw Error(code: ERR_STRIP_PK_HEADER, reason: "Provided public key is empty")
		}
		
		var byteArray = [UInt8](keyData)
		
		var index = 0
		guard byteArray[index] == 0x30 else {
			
			throw Error(code: ERR_STRIP_PK_HEADER, reason: "Provided key doesn't have a valid ASN.1 structure (first byte should be 0x30 == SEQUENCE)")
		}
		
		index += 1
		if byteArray[index] > 0x80 {
			index += Int(byteArray[index]) - 0x80 + 1
		} else {
			index += 1
		}
		
		// If current byte marks an integer (0x02), it means the key doesn't have a X509 header and just
		// contains its modulo & public exponent. In this case, we can just return the provided DER data as is.
		if Int(byteArray[index]) == 0x02 {
			return keyData
		}
		
		// Now that we've excluded the possibility of headerless key, we're looking for a valid X509 header sequence.
		// It should look like this:
		// 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
		guard Int(byteArray[index]) == 0x30 else {
			
			throw Error(code: ERR_STRIP_PK_HEADER, reason: "Provided key doesn't have a valid X509 header")
		}
		
		index += 15
		if byteArray[index] != 0x03 {
			
			throw Error(code: ERR_STRIP_PK_HEADER, reason: "Invalid byte at index \(index - 1) (\(byteArray[index - 1])) for public key header")
		}
		
		index += 1
		if byteArray[index] > 0x80 {
			index += Int(byteArray[index]) - 0x80 + 1
		} else {
			index += 1
		}
		
		guard byteArray[index] == 0 else {
			
			throw Error(code: ERR_STRIP_PK_HEADER, reason: "Invalid byte at index \(index - 1) (\(byteArray[index - 1])) for public key header")
		}
		
		index += 1
		
		let strippedKeyBytes = [UInt8](byteArray[index...keyData.count - 1])
		let data = Data(bytes: UnsafePointer<UInt8>(strippedKeyBytes), count: keyData.count - index)
		
		return data
	}
    
    // SecKeyCreateEncrypted uses the public key and modulus as Additional authenticated data.
    // This function extracts and creates an ASN1 sequence with these two bits of data
    // To be used for cross platform support.
    static func getPublicKeyDataFrom(privateKey keyData: Data) throws -> Data {
        
        let count = keyData.count / MemoryLayout<CUnsignedChar>.size
        
        guard count > 0 else {
            
            throw Error(code: ERR_STRIP_PK_HEADER, reason: "Provided public key is empty")
        }
        
        // Get the length of the total length bytes and move to object after them.
        var byteArray = [UInt8](keyData)
        var index = 1
        if byteArray[index] > 0x80 {
            index += Int(byteArray[index]) - 0x80 + 1
        } else {
            index += 1
        }
        // Skip the RSA version
        index += 3
        guard Int(byteArray[index]) == 0x02 else {
            throw Error(code: ERR_STRIP_PK_HEADER, reason: "Invalid private key ANS1")
        }
        var publicKeyLength = 0
        var lengthOfLength = 0
        index += 1
        // Add the modulus length and bytes to the stripped bytes
        if byteArray[index]  <= 0x80 { // short form
            publicKeyLength = Int(byteArray[index])
            lengthOfLength = 1
        } else {
            lengthOfLength = Int(byteArray[index]) - 0x80 + 1
            var result: Int = 0
            for i in 1..<(lengthOfLength) {
                result = 256 * result + Int(byteArray[index + i])
            }
            publicKeyLength = result
        }
        var strippedKeyBytes = [UInt8](byteArray[(index-1)..<(index+lengthOfLength+publicKeyLength)])
        index += lengthOfLength + publicKeyLength
        
        // Add the publicExponent length and bytes to the stripped bytes
        let exponentLength = Int(byteArray[index + 1])
        strippedKeyBytes += [UInt8](byteArray[index..<(index+2+exponentLength)])
        let sequenceCount = strippedKeyBytes.count
        
        // Calculating the length representation and create an ASN1 sequence for the modulus and exponent.
        let sequenceBytes: [UInt8]
        if sequenceCount < 128 {
            sequenceBytes = [0x30, UInt8(sequenceCount)]
        } else if sequenceCount <= 255 {
            sequenceBytes = [0x30, 0x81, UInt8(sequenceCount)]
        } else {
            let mostSigByte = strippedKeyBytes.count/256
            let leastSigByte = strippedKeyBytes.count % 256
            sequenceBytes = [0x30, 0x82, UInt8(mostSigByte), UInt8(leastSigByte)]
        }
        strippedKeyBytes = sequenceBytes + strippedKeyBytes
        return Data(bytes: strippedKeyBytes, count: strippedKeyBytes.count)
    }
	
}

extension String {
	
	///
	/// Split a string to a specified length.
	///
	///	- Parameters:
	///		- length:				Length of each split string.
	///
	///	- Returns:					`[String]` containing each string.
	///
	func split(to length: Int) -> [String] {
		
		var result = [String]()
		var collectedCharacters = [Character]()
		collectedCharacters.reserveCapacity(length)
		var count = 0
		
		for character in self {
			collectedCharacters.append(character)
			count += 1
			if count == length {
				// Reached the desired length
				count = 0
				result.append(String(collectedCharacters))
				collectedCharacters.removeAll(keepingCapacity: true)
			}
		}
		
		// Append the remainder
		if !collectedCharacters.isEmpty {
			result.append(String(collectedCharacters))
		}
		
		return result
	}
}


// MARK: -

#if !os(Linux)

	// MARK: -- CFString Extension for Hashing
	
	///
	/// Extension to CFString to make it hashable.
	///
	extension CFString: Hashable {
		
		/// Return the hash value of a CFString
		public var hashValue: Int {
			return (self as String).hashValue
		}
		
		/// Comparison of CFStrings
		static public func == (lhs: CFString, rhs: CFString) -> Bool {
			return lhs as String == rhs as String
		}
	}
	
#endif
