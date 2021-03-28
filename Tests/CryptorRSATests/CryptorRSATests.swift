//
//  CryptorRSATests.swift
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

import XCTest
#if os(Linux)
    import OpenSSL
#endif

@testable import CryptorRSA

@available(macOS 10.12, iOS 10.3, watchOS 3.3, tvOS 12.0, *)
class CryptorRSATests: XCTestCase {
	
	/// Test for bundle usage.
    static var useBundles: Bool {
        if let bundle = CryptorRSATests.bundle {
            let path = bundle.path(forResource: "public", ofType: "der")
            return path != nil
        } else {
            return false
        }
    }
    
    #if os(Linux)
        static let bundle: Bundle? = nil
    #else
        static let bundle: Bundle? = Bundle(for: CryptorRSATests.self)
    #endif
	
	///
	/// Platform independent utility function to locate test files.
	///
	/// - Parameters:
	///		- resource:			The name of the resource to find.
	///		- ofType:			The type (i.e. extension) of the resource.
	///
	///	- Returns:	URL for the resource or nil if a path to the resource cannot be found.
	///
    static public func getFilePath(for resource: String, ofType: String) -> URL? {
        
        var path: URL
        
        if CryptorRSATests.useBundles, let bundle = CryptorRSATests.bundle {
            guard let bPath = bundle.path(forResource: resource, ofType: ofType) else {
                
                return nil
            }
            path = URL(fileURLWithPath: bPath)
            
        } else {
            
            path = URL(fileURLWithPath: #file).appendingPathComponent("../keys/" + resource + "." + ofType).standardized
        }
        
        return path
    }

    
	// MARK: Public Key Tests
	
	func test_public_initWithData() throws {
		
        let path = CryptorRSATests.getFilePath(for: "public", ofType: "der")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let data = try Data(contentsOf: filePath)
            let publicKey = try? CryptorRSA.createPublicKey(with: data)
            XCTAssertNotNil(publicKey)
            XCTAssertTrue(publicKey?.type == .publicType)
        }
	}
	
    // Certificate is PEM
	func test_public_initWithCertData() throws {
		
		let path = CryptorRSATests.getFilePath(for: "staging", ofType: "cer")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let data = try Data(contentsOf: filePath)
            let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: data)
            XCTAssertNotNil(publicKey)
            XCTAssertTrue(publicKey?.type == .publicType)
        }
	}
	
    // Certificate is PEM
	func test_public_initWithCertData2() throws {
		
		let path = CryptorRSATests.getFilePath(for: "staging2", ofType: "cer")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let data = try Data(contentsOf: filePath)
            let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: data)
            XCTAssertNotNil(publicKey)
            XCTAssertTrue(publicKey?.type == .publicType)
        }
	}
	
    // Public key is base64 encoded DER
	func test_public_initWithBase64String() throws {
		
        let path = CryptorRSATests.getFilePath(for: "public-base64", ofType: "txt")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let str = try String(contentsOf: filePath, encoding: .utf8)
            let publicKey = try? CryptorRSA.createPublicKey(withBase64: str)
            XCTAssertNotNil(publicKey)
            XCTAssertTrue(publicKey?.type == .publicType)
        }
	}
	

	func test_public_initWithBase64StringWhichContainsNewLines() throws {
		
        let path = CryptorRSATests.getFilePath(for: "public-base64-newlines", ofType: "txt")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let str = try String(contentsOf: filePath, encoding: .utf8)
            let publicKey = try? CryptorRSA.createPublicKey(withBase64: str)
            XCTAssertNotNil(publicKey)
            XCTAssertTrue(publicKey?.type == .publicType)
        }
	}
	
	func test_public_initWithPEMString() throws {
		
        let path = CryptorRSATests.getFilePath(for: "public", ofType: "pem")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let str = try String(contentsOf: filePath, encoding: .utf8)
            let publicKey = try? CryptorRSA.createPublicKey(withPEM: str)
            XCTAssertNotNil(publicKey)
            XCTAssertTrue(publicKey?.type == .publicType)
        }
	}
	
	func test_public_initWithPEMName() throws {
		
		if CryptorRSATests.useBundles, let bundle = CryptorRSATests.bundle {
			
			let publicKey = try? CryptorRSA.createPublicKey(withPEMNamed: "public", in: bundle)
			XCTAssertNotNil(publicKey)
		
		} else {
			
			let publicKey = try? CryptorRSA.createPublicKey(withPEMNamed: "public", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}
	}
	
	func test_public_initWithDERName() throws {
		
		if CryptorRSATests.useBundles, let bundle = CryptorRSATests.bundle {
			
			let publicKey = try? CryptorRSA.createPublicKey(withDERNamed: "public", in: bundle)
			XCTAssertNotNil(publicKey)
			
		} else {
			
			let publicKey = try? CryptorRSA.createPublicKey(withDERNamed: "public", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}
		
	}

    // This function tests stripping a PEM string that's already been stripped...
	func test_public_initWithPEMStringHeaderless() throws {
		
        let path = CryptorRSATests.getFilePath(for: "public-headerless", ofType: "pem")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let str = try String(contentsOf: filePath, encoding: .utf8)
            let publicKey = try? CryptorRSA.createPublicKey(withPEM: str)
            XCTAssertNotNil(publicKey)
            XCTAssertTrue(publicKey?.type == .publicType)
        }
	}
	
	func test_publicKeysFromComplexPEMFileWorksCorrectly() {
		
        guard let input = CryptorRSATests.pemKeyString(name: "multiple-keys-testcase") else {
            XCTFail()
            return
        }
        
		let keys = CryptorRSA.PublicKey.publicKeys(withPEM: input)
		XCTAssertEqual(keys.count, 9)
		
		for publicKey in keys {
			XCTAssertTrue(publicKey.type == .publicType)
		}
	}
	
	func test_publicKeysFromEmptyPEMFileReturnsEmptyArray() {
		
		let keys = CryptorRSA.PublicKey.publicKeys(withPEM: "")
		XCTAssertEqual(keys.count, 0)
	}
	

	func test_public_initWithCertificateName() throws {
		
		if CryptorRSATests.useBundles, let bundle = CryptorRSATests.bundle {
			
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging", in: bundle)
			XCTAssertNotNil(publicKey)
			
		} else {
			
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}
		
	}
	
	func test_public_initWithCertificateName2() throws {
		
		if CryptorRSATests.useBundles, let bundle = CryptorRSATests.bundle {
			
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging2", in: bundle)
			XCTAssertNotNil(publicKey)
			
		} else {
			
			let publicKey = try? CryptorRSA.createPublicKey(extractingFrom: "staging2", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(publicKey)
		}
		
	}
	
	// MARK: Private Key Tests
	
	func test_private_initWithPEMString() throws {
		
        let path = CryptorRSATests.getFilePath(for: "private", ofType: "pem")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let str = try String(contentsOf: filePath, encoding: .utf8)
            let privateKey = try? CryptorRSA.createPrivateKey(withPEM: str)
            XCTAssertNotNil(privateKey)
            XCTAssertTrue(privateKey!.type == .privateType)
        }
	}
    
    func test_private_initWithBase64() throws {
        
        let path = CryptorRSATests.getFilePath(for: "private", ofType: "pem")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let str = try String(contentsOf: filePath, encoding: .utf8)
            let strippedstr = String(str.filter { !" \n\t\r".contains($0) })
            let headerlessStr = String(strippedstr.dropFirst(28).dropLast(26))
            let privateKey = try? CryptorRSA.createPrivateKey(withBase64: headerlessStr)
            XCTAssertNotNil(privateKey)
            XCTAssertTrue(privateKey?.type == .privateType)
        }
    }
	
	func test_private_initWithPEMStringHeaderless() throws {
		
        let path = CryptorRSATests.getFilePath(for: "private-headerless", ofType: "pem")
        XCTAssertNotNil(path)
        
        if let filePath = path {
            let str = try String(contentsOf: filePath, encoding: .utf8)
            let privateKey = try? CryptorRSA.createPrivateKey(withPEM: str)
            XCTAssertNotNil(privateKey)
            XCTAssertTrue(privateKey!.type == .privateType)
        }
	}
	
	func test_private_initWithPKCS8() throws {
		
		let path = URL(fileURLWithPath: #file).appendingPathComponent("../keys/pkcs8.pem").standardized
		XCTAssertNotNil(path)
		
		let str = try String(contentsOf: path, encoding: .utf8)
		let privateKey = try? CryptorRSA.createPrivateKey(withPEM: str)
		XCTAssertNotNil(privateKey)
		XCTAssertTrue(privateKey?.type == .privateType)
	}
	
	func test_private_initWithPEMName() throws {
		
		if CryptorRSATests.useBundles, let bundle = CryptorRSATests.bundle {
			
			let privateKey = try? CryptorRSA.createPrivateKey(withPEMNamed: "private", in: bundle)
			XCTAssertNotNil(privateKey)
			
		} else {
			
			let privateKey = try? CryptorRSA.createPrivateKey(withPEMNamed: "private", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(privateKey)
		}
		
	}
	
	func test_private_initWithDERName() throws {
		
		if CryptorRSATests.useBundles, let bundle = CryptorRSATests.bundle {
			
			let privateKey = try? CryptorRSA.createPrivateKey(withDERNamed: "private", in: bundle)
			XCTAssertNotNil(privateKey)
			
		} else {
			
			let privateKey = try? CryptorRSA.createPrivateKey(withDERNamed: "private", onPath: "../../../Tests/CryptorRSATests/keys/")
			XCTAssertNotNil(privateKey)
		}
		
	}

	// MARK: Encyption/Decryption Tests
    
    let publicKey: CryptorRSA.PublicKey? = try? CryptorRSATests.publicKey(name: "public")
    let privateKey: CryptorRSA.PrivateKey? = try? CryptorRSATests.privateKey(name: "private")
	
	func test_simpleEncryption() throws {
		
		let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
                                                      (.sha224, ".sha224"),
                                                      (.sha256, ".sha256"),
                                                      (.sha384, ".sha384"),
                                                      (.gcm, "gcm"),
                                                      /*(.sha512, ".sha512")*/]
		// Test all the algorithms available...
		//	Note: .sha512 encryption appears to be broken internally on Apple platforms, so we skip it...
		for (algorithm, name) in algorithms {
		
			print("Testing algorithm: \(name)")
			let str = "Plain Text"
			let plainText = try CryptorRSA.createPlaintext(with: str, using: .utf8)
            
            guard let publicKey = self.publicKey,
                  let privateKey = self.privateKey else {
                XCTFail("Could not find key")
                return
            }
            
			let encrypted = try plainText.encrypted(with: publicKey, algorithm: algorithm)
			XCTAssertNotNil(encrypted)
			let decrypted = try encrypted?.decrypted(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(decrypted)
			let decryptedString = try decrypted!.string(using: .utf8)
			XCTAssertEqual(decryptedString, str)
			print("Test of algorithm: \(name) succeeded")
		}
	}
	
	func test_linuxEncryptedGCM() throws {
		
		print("Testing linux encrypted GCM")
		let linuxEncrypted = try CryptorRSA.createEncrypted(with: "toylrkUlMuNyqERzkUTl/kX88eYnaZFO2cD7vO3LUqZJ/GhsSmgDudQhS5CsZGEwPVnrrZ77S7j5ksikouJm9MpurBZZYJN1iOGLjDfam8Vtz6iYpZ7fLdrGMWz/ytrqxcUTeHkXKJ+Hx/XHf+SLQN79Yw8XWAE5qowRnTdZy9x16J7czi4MJW5URO/cFA/nkKStvOSzZRgd9WiqOos=")
		
		guard let privateKey = self.privateKey else {
				XCTFail("Could not find key")
				return
		}
		let decrypted = try linuxEncrypted.decrypted(with: privateKey, algorithm: .gcm)
		XCTAssertNotNil(decrypted)
		let decryptedString = try decrypted?.string(using: .utf8)
		XCTAssertEqual(decryptedString, "LinuxEncrypted")
		print("Test of GCM algorithm succeeded")
	}

	func test_MacEncryptedGCM() throws {
		
		print("Testing MacOS encrypted GCM")
		let macEncrypted = try CryptorRSA.createEncrypted(with: "SfM0Tg3M4mU0EFoz1ZiriUShCQbyT+aITE8FO+vvIwoNHyI/OWsOxyVxIv4K86tFuDrR9ORSiYcc8O29pOPbpcpGQEo+0EsVjiDwvbrDsIXdOWtiX8hbe/vjvuC8QfYaA5K8OiSlLyMtZGpyegKiROjHXxuVQfk4EgGI2IANARgrO191bar87742fgO0w55ILuNLXvU+/kYXe7DV")
		
		guard let privateKey = self.privateKey else {
			XCTFail("Could not find key")
			return
		}
		let decrypted = try macEncrypted.decrypted(with: privateKey, algorithm: .gcm)
		XCTAssertNotNil(decrypted)
		let decryptedString = try decrypted?.string(using: .utf8)
		XCTAssertEqual(decryptedString, "MacEncrypted")
		print("Test of GCM algorithm succeeded")
	}
	
	func test_4096bitRSAKeyMacEncryptedGCM() throws {
		
		let rsaPrivKey = """
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
"""
		
		print("Testing MacOS encrypted GCM")
		let macEncrypted = try CryptorRSA.createEncrypted(with: "u7SgVzag0RL3rN36FPRWwKQKZ0iCvY09Zy4FECrpOCoDHqPPmMEuzhkjVswUVceGCcN8KZ2mq/ABE8CiQId6+zhUDt8/kCkToOz8enIg8g4T6p/ZDhPbP6qPp7s75Fp3rqIxr7EwT/12drtxY3XLJZXehYysrpxRv1qkXE067Iuw+Mp8g/jP1bZF5FmL7a6CdWvG+o3kJ1xTvz+ySO2GVeErEbLf16rP+zVEfdxr/uWv6qWeyVNKf7Mn14SEbeNhRXzkFIraYFjZd4+EZBdTkFk/muL+xyxJgf+phaKWM18l1bno/wxiGmxYrfi0vMWl/6HpMvdMsGoUDhcTrGovhawF12dD8P34MpWowebon0TufA43I42MPM7eMagEdGnCNoY4QQP3m31gUfUUb6261yHQsE8cookBoE9f7+BqrWkUYjvqcTO7JsBCNEQDOyvmUzZBIra13SpvWW0gufmwJ4vDMd95kpCKw2RbRAo4+Cg9oRVln3Mo1u8hEwh4DdlCLU0y2Idc2Gml36IOwKnjBPn7PQgD7FiGarsMfNwkqkgtvQYLDcTmiGk/e7nf8Ds9ujnZquBD5xLS5Jym4j02tw4hAJQdwPiqKzlIDVF1ZYX1jd8XDPk3Iy9GcNOAUuhWd09joutu1BnnrWUaErOjVx1K0yRqrbRgELxzALCLpUoVLaf/ZbSI6q78RyRC2HgKGIs61lL7Vl1TVg==")
		
		let privateKey = try CryptorRSA.createPrivateKey(withPEM: rsaPrivKey)
		let decrypted = try macEncrypted.decrypted(with: privateKey, algorithm: .gcm)
		XCTAssertNotNil(decrypted)
		let decryptedString = try decrypted?.string(using: .utf8)
		XCTAssertEqual(decryptedString, "Plain Text")
		print("Test of GCM algorithm succeeded")
	}

	func test_longStringEncryption() throws {

		let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
                                                      (.sha224, ".sha224"),
                                                      (.sha256, ".sha256"),
                                                      (.sha384, ".sha384"),
                                                      (.gcm, "gcm"),
                                                      /*(.sha512, ".sha512")*/]
		// Test all the algorithms available...
		//	Note: .sha512 encryption appears to be broken internally on Apple platforms, so we skip it...
		for (algorithm, name) in algorithms {
			
			print("Testing algorithm: \(name)")
			let str = [String](repeating: "a", count: 9999).joined(separator: "")
			let plainText = try CryptorRSA.createPlaintext(with: str, using: .utf8)
		
            guard let publicKey = self.publicKey,
                let privateKey = self.privateKey else {
                    XCTFail("Could not find key")
                    return
            }
            
			let encrypted = try plainText.encrypted(with: publicKey, algorithm: algorithm)
			XCTAssertNotNil(encrypted)
			let decrypted = try encrypted!.decrypted(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(decrypted)
			let decryptedString = try decrypted!.string(using: .utf8)
			XCTAssertEqual(decryptedString, str)
			print("Test of algorithm: \(name) succeeded")
		}
	}
	
	func test_randomByteEncryption() throws {
		
		let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
                                                      (.sha224, ".sha224"),
                                                      (.sha256, ".sha256"),
                                                      (.sha384, ".sha384"),
                                                      (.gcm, "gcm"),
                                                      /*(.sha512, ".sha512")*/]
		// Test all the algorithms available...
		//	Note: .sha512 encryption appears to be broken internally on Apple platforms, so we skip it...
		for (algorithm, name) in algorithms {
			
			print("Testing algorithm: \(name)")
			let data = CryptorRSATests.randomData(count: 2048)
			let plainData = CryptorRSA.createPlaintext(with: data)
		
            guard let publicKey = self.publicKey,
                let privateKey = self.privateKey else {
                    XCTFail("Could not find key")
                    return
            }
            
			let encrypted = try plainData.encrypted(with: publicKey, algorithm: algorithm)
			XCTAssertNotNil(encrypted)
			let decrypted = try encrypted!.decrypted(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(decrypted)
			XCTAssertEqual(decrypted!.data, data)
			print("Test of algorithm: \(name) succeeded")
		}
	}
	
	// MARK: Signing/Verification Tests
	
	func test_signVerifyAllDigestTypes() throws {
		
		let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
                                                      (.sha224, ".sha224"),
                                                      (.sha256, ".sha256"),
                                                      (.sha384, ".sha384"),
                                                      (.sha512, ".sha512"),
                                                      (.gcm, ".gcm")]
        guard let publicKey = self.publicKey,
            let privateKey = self.privateKey else {
                XCTFail("Could not find key")
                return
        }

		// Test all the algorithms available...
		for (algorithm, name) in algorithms {

			print("Testing algorithm: \(name)")
			let data = CryptorRSATests.randomData(count: 8192)
			let message = CryptorRSA.createPlaintext(with: data)
			let signature = try message.signed(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(signature)
			let verificationResult = try message.verify(with: publicKey, signature: signature!, algorithm: algorithm)
			XCTAssertTrue(verificationResult)
			print("Test of algorithm: \(name) succeeded")
		}
	}
	
	func test_signVerifyBase64() throws {
		
		let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
                                                      (.sha224, ".sha224"),
                                                      (.sha256, ".sha256"),
                                                      (.sha384, ".sha384"),
                                                      (.sha512, ".sha512"),
                                                      (.gcm, ".gcm")]
	
        guard let publicKey = self.publicKey,
            let privateKey = self.privateKey else {
                XCTFail("Could not find key")
                return
        }
        
		// Test all the algorithms available...
		for (algorithm, name) in algorithms {
			
			print("Testing algorithm: \(name)")
			let data = CryptorRSATests.randomData(count: 8192)
			let message = CryptorRSA.createPlaintext(with: data)
			let signature = try message.signed(with: privateKey, algorithm: algorithm)
			XCTAssertNotNil(signature)
			XCTAssertEqual(signature!.base64String, signature!.data.base64EncodedString())
			let verificationResult = try message.verify(with: publicKey, signature: signature!, algorithm: algorithm)
			XCTAssertTrue(verificationResult)
			print("Test of algorithm: \(name) succeeded")
		}
	}
	
	func test_signVerifyAllDigestTypesPSS() throws {
		
		// PSS is only supported from swift 4.1 onwards
		#if !swift(>=4.1) 
			return
		#else
		
			let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
														  (.sha224, ".sha224"),
														  (.sha256, ".sha256"),
														  (.sha384, ".sha384"),
														  (.gcm, ".gcm"),
														/*(.sha512, ".sha512")*/]
			// Test all the algorithms available...
			//	Note: .sha512 pss appears to be broken internally on Apple platforms, so we skip it...
			guard let publicKey = self.publicKey,
				let privateKey = self.privateKey else {
					XCTFail("Could not find key")
					return
			}
		
			// Test all the algorithms available...
			for (algorithm, name) in algorithms {
				
				print("Testing algorithm: \(name)")
				let data = CryptorRSATests.randomData(count: 8192)
				let message = CryptorRSA.createPlaintext(with: data)
				let signature = try message.signed(with: privateKey, algorithm: algorithm, usePSS: true)
				XCTAssertNotNil(signature)
				let verificationResult = try message.verify(with: publicKey, signature: signature!, algorithm: algorithm, usePSS: true)
				XCTAssertTrue(verificationResult)
				print("Test of algorithm: \(name) succeeded")
			}
		#endif
	}
	
	func test_signVerifyBase64PSS() throws {
		
		// PSS is only supported from swift 4.1 onwards
		#if !swift(>=4.1) 
			return
		#else
		
			let algorithms: [(Data.Algorithm, String)] = [(.sha1, ".sha1"),
														  (.sha224, ".sha224"),
														  (.sha256, ".sha256"),
														  (.sha384, ".sha384"),
														  (.gcm, ".gcm"),
														/*(.sha512, ".sha512")*/]
			// Test all the algorithms available...
			//	Note: .sha512 pss appears to be broken internally on Apple platforms, so we skip it...
		
			guard let publicKey = self.publicKey,
				let privateKey = self.privateKey else {
					XCTFail("Could not find key")
					return
			}
		
			// Test all the algorithms available...
			for (algorithm, name) in algorithms {
				
				print("Testing algorithm: \(name)")
				let data = CryptorRSATests.randomData(count: 8192)
				let message = CryptorRSA.createPlaintext(with: data)
				let signature = try message.signed(with: privateKey, algorithm: algorithm, usePSS: true)
				XCTAssertNotNil(signature)
				XCTAssertEqual(signature!.base64String, signature!.data.base64EncodedString())
				let verificationResult = try message.verify(with: publicKey, signature: signature!, algorithm: algorithm, usePSS: true)
				XCTAssertTrue(verificationResult)
				print("Test of algorithm: \(name) succeeded")
			}
		#endif
	}
	
	func test_verifyExtenalPSSSignature() {
		
		// PSS is only supported from swift 4.1 onwards
		#if !swift(>=4.1) 
			return
		#else
		
			guard let publicKey = self.publicKey else {
				XCTFail("Could not find key")
				return
			}
			// Generated by jwt.io
			let externalMessage = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
			let externalSignature = "Itey9AhjNgb1owBaVsTE-7NrZY1c7AJtp990w4AJRZWMOeX-2UiVdil9vflW7BkduRXMA83hCdhQjqzvnJGhxEVllZshPYvueW0otxzI-wl4fPY6ai6qiBh9JzDwFlb9IHyIDGhr3HHKaMjYEwpt8VJYxzEcHwdGg34aczspM0U"
			let message = CryptorRSA.createPlaintext(with: Data(externalMessage.utf8))
			let signature = CryptorRSA.createSigned(with: Data(base64urlEncoded: externalSignature)!)
			do {
				let verificationResult = try message.verify(with: publicKey, signature: signature, algorithm: .sha256, usePSS: true)
				XCTAssertTrue(verificationResult)
			} catch {
				XCTFail("Error thrown during verification: \(error)")
			}
		#endif
	}

    func test_verifyAppIDToken() throws {
        
        let certificatePEM = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn4Tw7golPpKj+VSQIiRT
            RApbtCMyn28btLu9nHQzf32J1niY/uJZZbo5O+MsekNPHu5qmLBFCS0M3HcYeKAk
            OZtu7z9W1Lkronpt7WBWu+7qnGZm2vPw9rOUflZjGS5Qh9RinPJ9S5tnOrO5VapA
            7Rb2Q6EU3scgsDFvVaxBERf6IuDXgwYZp+tCcmBccEDBIfQ44mvu/6dHPwAUICJw
            3y/S4hqv2VEDslEdAJm2kj+WRIYooFBPVlp7371iVZtmV9cStBLW5igBvePe5ots
            lU7tI2NCoSxFONjF+kGxO2S8mbBzADTBXaAE7clHorp6nRj8rIxHzD0V3+W8mp2W
            1QIDAQAB
            -----END PUBLIC KEY-----
            """
        
        guard let tokenPublicKey = try? CryptorRSA.createPublicKey(withPEM: certificatePEM) else {
            XCTFail("Public ket not made")
            return
        }

        XCTAssertTrue(tokenPublicKey.type == .publicType)
        
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJhcHBJZC0xNTA0Njg1OTYxMDAwIn0.eyJpc3MiOiJhcHBpZC1vYXV0aC5uZy5ibHVlbWl4Lm5ldCIsImF1ZCI6IjUzOGU4NTI2YTcwNDdjMWM5ZTEzNDZhYzQ1MjA2NmQxYmE1ZmQzNTEiLCJleHAiOjE1MTgxOTkzNTgsInRlbmFudCI6ImQ3YmMzMjJjLWIyMjQtNDFjMS05MWVhLWZjNjM4YWUyYWQ0ZCIsImlhdCI6MTUxODE5NTc1OCwiZW1haWwiOiJhYXJvbi5saWJlcmF0b3JlQGdtYWlsLmNvbSIsIm5hbWUiOiJBYXJvbiBMaWJlcmF0b3JlIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS8tWGRVSXFkTWtDV0EvQUFBQUFBQUFBQUkvQUFBQUFBQUFBQUEvNDI1MnJzY2J2NU0vcGhvdG8uanBnIiwic3ViIjoiNGZiOTY0NDUtMGIzYy00Mzg2LWI3MmEtNTk2YmIzYTlkNDUwIiwiaWRlbnRpdGllcyI6W3sicHJvdmlkZXIiOiJnb29nbGUiLCJpZCI6IjEwODQ2MDkwMTMxMTMxNzgyOTg4NCJ9XSwiYW1yIjpbImdvb2dsZSJdLCJvYXV0aF9jbGllbnQiOnsibmFtZSI6IldhdHNvbiBUb25lIEFuYWx5emVyIFJLQUpHIiwidHlwZSI6Im1vYmlsZWFwcCIsInNvZnR3YXJlX2lkIjoiY29tLmlibS5XYXRzb25Ub25lQW5hbHl6ZXJSS0FKRyIsInNvZnR3YXJlX3ZlcnNpb24iOiIxLjAiLCJkZXZpY2VfaWQiOiI3QTk2QjJDQi1DNkI4LTRCNTYtQjA0Ri1FMTMwQjZDMkUxMUMiLCJkZXZpY2VfbW9kZWwiOiJpUGhvbmUiLCJkZXZpY2Vfb3MiOiJpT1MiLCJkZXZpY2Vfb3NfdmVyc2lvbiI6IjExLjIifX0.RTK5wV0b0mtbRayKg9IdGCnGXoA7bn4Gdx-YIQjaaELWJwpla2x1R1hMvL5It-MKMt_pyejzkdoTKR3v_VF4IMwnBWz83d0u6TVs28TbrgHAkXy6sAypIfEKc4gLOSHXkUBYREH2pbJSguxZNTwqKe_PKRSYtG0QrtffPUsESfnGkdfHdUsSigMjX5s5En8fLCGiNSQF2uyYREDFE6T0w5P3W5MR_Scloyhik1q7nv91PzlJ6Rn9_0F12zjzvPMTt7bobTdokaFVPcqjFWHJc4YCw-bzdBCxtzHxf3oVXeJzCzPNb_nOehZu-u7ue54NbYwcoZ_bokmsjCnQbFE_QA"
        
        let tokenParts = token.split(separator: ".")
        // JWT token should have 3 parts
        XCTAssertTrue(tokenParts.count == 3)
        
        // Signed message is the first two components of the token
        let messageData = (String(tokenParts[0] + "." + tokenParts[1]).data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue))!)
        XCTAssertNotNil(messageData)
        
        // signature is 3rd component
        let sigStr = String(tokenParts[2])
        // JWT gets rid of any base64 padding, so add padding to allow for proper decoding
        var sig = sigStr.padding(toLength: ((sigStr.count+3)/4)*4, withPad: "=", startingAt: 0)
        
        // JWT also does base64url encoding, so make the proper replacements so its proper base64 encoding
        sig = sig.replacingOccurrences(of: "-", with: "+")
        sig = sig.replacingOccurrences(of: "_", with: "/")
        
        guard let sigData = Data(base64Encoded: sig) else {
            XCTFail("Unable to create Signature Data")
            return
        }
        
        let message = CryptorRSA.createPlaintext(with: messageData)
        XCTAssertNotNil(message)
        
        let signature = CryptorRSA.createSigned(with: sigData)
        XCTAssertNotNil(signature)
        
        let verificationResult = try message.verify(with: tokenPublicKey, signature: signature, algorithm: .sha256)
        XCTAssertTrue(verificationResult)
    }
    
	func test_makeKeyPair() {
		let bitSizes: [CryptorRSA.RSAKey.KeySize] = [.bits1024, .bits2048, .bits3072, .bits4096]
		for bitSize in bitSizes {
			do {
				let (tempPrivKey, tempPubKey) = try CryptorRSA.makeKeyPair(bitSize)
				let privString = tempPrivKey.pemString
				let pubString = tempPubKey.pemString
				do {
					let privKey = try CryptorRSA.createPrivateKey(withPEM: privString)
					do {
						let pubKey = try CryptorRSA.createPublicKey(withPEM: pubString)
						let str = "Plain Text"
						do {
							let plainText = try CryptorRSA.createPlaintext(with: str, using: .utf8)
							let encrypted = try plainText.encrypted(with: pubKey, algorithm: .gcm)
							let decrypted = try encrypted?.decrypted(with: privKey, algorithm: .gcm)
							XCTAssertNotNil(decrypted)
							let decryptedString = try decrypted?.string(using: .utf8)
							XCTAssertEqual(decryptedString, str)
						} catch {
							XCTFail("Encryption / decryption failed for bitSize: \(bitSize.bits): \(error)")
						}
					} catch {
						XCTFail("createPublicKey failed for bitSize: \(bitSize.bits): \(error), PEM: '\(pubString)'")
					}
				} catch {
					XCTFail("createPrivateKey failed for bitSize: \(bitSize.bits): \(error), PEM: '\(privString)'")
				}
			} catch {
				XCTFail("test_makeKeyPair failed for bitSize: \(bitSize.bits), with error: \(error)")
			}
		}
		
		
	}

	// Test that when the data for a key has a value of 0x30 in byte 27, it is not
	// erroneously interpreted as pkcs8 by stripX509CertificateHeader (whereby the
	// first 26 bytes are dropped).
	// See https://github.com/IBM-Swift/BlueRSA/issues/52
	func testSpecificPEM() {
		let pemString = """
-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEAsdrDG5WLDpbIa5cHIwhFvkkwpWG3ULikyMsNWUq0/d1uaRdlemgvS
u21PqwDhBsgFjBn8ENQsOQpr5Bm2tC2XIchKPjEnsA3WsQ2iIkbDzrmbj5r2z1iiy
n/veMZEG0+Dg5H91I+2SG7c406rUgU00py/Y/C/aQCJonhpEolvuF3tgUt6/6X1mz
Y2ANwBzm3Zv9JoK0nAWZFqTkj9WrUXQprBi3G/mTLMaOScZzSig+rr8uxyl3TnV+X
bFuqD6hweWrCDOWJFZOHzflflCN/dFGHcUZqJNygjSY0LBBN7G2ES6XRlrr0OPypU
otmFEXJ1djQdlAVLc/LofhpVdXKW8zjm/Gj4guSYDiNNSSG8KgpCbTPJ4ZQGiTrx2
qse4PDC6PckHebpTXMUYSXLacoTEpAI9EONIuG6ThOkIyGO8elHVknhkZZZD0SIC3
jK/J8XlsTSWFGkif8W0PQJ5amyK7C/8eWZFwA7gLpNvR4BqnsY4a+dIw4a/HD0RKQ
AqJRAgMBAAE=
-----END RSA PUBLIC KEY-----
"""
		let data1 = Data(base64Encoded: pemString) ?? Data()
		print("data1 count=\(data1.count)")
		do {
			let pubKey = try CryptorRSA.createPublicKey(withPEM: pemString)
			print("pemString1 successful")
		} catch {
			XCTFail("Error creating public key from pemString: \(error)")
		}
	}

	// MARK: Test Utilities
	
	struct TestError: Error {
		let description: String
	}
	
	static public func pemKeyString(name: String) -> String? {
		
        guard let path = CryptorRSATests.getFilePath(for: name, ofType: "pem") else {
            XCTFail("Could not create pemKeyString")
            return nil
        }
        
        XCTAssertNotNil(path)
        
        guard let returnValue: String = try? String(contentsOfFile: path.path, encoding: String.Encoding.utf8) else {
            XCTFail("Could not create returnValue")
            return nil
        }
        
        XCTAssertNotNil(returnValue)
        
        return returnValue
	}
	
	static public func derKeyData(name: String) -> Data? {
		
        guard let path = CryptorRSATests.getFilePath(for: name, ofType: "der") else {
            XCTFail("Could not get file path")
            return nil
        }
        
        guard let returnValue: Data = try? Data(contentsOf: URL(fileURLWithPath: path.path)) else {
            XCTFail("Could not create derKeyData")
            return nil
        }
        
        return returnValue
	}
    
    enum MyError : Error {
        case invalidPath
    }
	
	static public func publicKey(name: String) throws -> CryptorRSA.PublicKey {
		
        guard let path = CryptorRSATests.getFilePath(for: name, ofType: "pem") else {
            throw MyError.invalidPath
        }
        
        let pemString = try String(contentsOf: path, encoding: String.Encoding.ascii)
        return try CryptorRSA.createPublicKey(withPEM: pemString)
	}
	
	static public func privateKey(name: String) throws -> CryptorRSA.PrivateKey {
		
        guard let path = CryptorRSATests.getFilePath(for: name, ofType: "pem") else {
            throw MyError.invalidPath
        }
        
        let pemString = try String(contentsOf: path, encoding: String.Encoding.ascii)
        return try CryptorRSA.createPrivateKey(withPEM: pemString)
	}
	
	static public func randomData(count: Int) -> Data {
		
		var data = Data(count: count)
		data.withUnsafeMutableBytes { (bytes: UnsafeMutableRawBufferPointer) -> Void in
			guard let baseAddress = bytes.baseAddress else { return }
			#if os(Linux)
				_ = RAND_bytes(baseAddress.assumingMemoryBound(to: UInt8.self), Int32(count))
			#else
				_ = SecRandomCopyBytes(kSecRandomDefault, count, baseAddress.assumingMemoryBound(to: UInt8.self))
            #endif
		}
		return data
	}
	
	// MARK: Test Lists for Linux
	
	static var allTests : [(String, (CryptorRSATests) -> () throws -> Void)] {
        return [
            ("test_public_initWithData", test_public_initWithData),
            ("test_public_initWithCertData", test_public_initWithCertData),
            ("test_public_initWithCertData2", test_public_initWithCertData2),
            ("test_public_initWithBase64String", test_public_initWithBase64String),
            ("test_public_initWithBase64StringWhichContainsNewLines", test_public_initWithBase64StringWhichContainsNewLines),
            ("test_public_initWithPEMString", test_public_initWithPEMString),
            ("test_public_initWithPEMName", test_public_initWithPEMName),
            ("test_public_initWithDERName", test_public_initWithDERName),
//			("test_public_initWithPEMStringHeaderless", test_public_initWithPEMStringHeaderless),
//			("test_publicKeysFromComplexPEMFileWorksCorrectly", test_publicKeysFromComplexPEMFileWorksCorrectly),
            ("test_publicKeysFromEmptyPEMFileReturnsEmptyArray", test_publicKeysFromEmptyPEMFileReturnsEmptyArray),
            ("test_public_initWithCertificateName", test_public_initWithCertificateName),
            ("test_public_initWithCertificateName2", test_public_initWithCertificateName2),
            ("test_private_initWithPEMString", test_private_initWithPEMString),
            ("test_private_initWithBase64", test_private_initWithBase64),
//			("test_private_initWithPEMStringHeaderless", test_private_initWithPEMStringHeaderless),
            ("test_private_initWithPEMName", test_private_initWithPEMName),
            ("test_private_initWithDERName", test_private_initWithDERName),
            ("test_simpleEncryption", test_simpleEncryption),
            ("test_linuxEncryptedGCM", test_linuxEncryptedGCM),
            ("test_MacEncryptedGCM", test_MacEncryptedGCM),
            ("test_4096bitRSAKeyMacEncryptedGCM", test_4096bitRSAKeyMacEncryptedGCM),
            ("test_longStringEncryption", test_longStringEncryption),
            ("test_randomByteEncryption", test_randomByteEncryption),
			("test_signVerifyAllDigestTypes", test_signVerifyAllDigestTypes),
			("test_signVerifyBase64", test_signVerifyBase64),
			("test_signVerifyAllDigestTypesPSS", test_signVerifyAllDigestTypesPSS),
			("test_signVerifyBase64PSS", test_signVerifyBase64PSS),
			("test_verifyExtenalPSSSignature", test_verifyExtenalPSSSignature),
            ("test_verifyAppIDToken", test_verifyAppIDToken),
            ("test_makeKeyPair", test_makeKeyPair),
			("testSpecificPEM", testSpecificPEM),
        ]
    }
}

private extension Data {	
	
	func base64urlEncodedString() -> String {
		let result = self.base64EncodedString()
		return result.replacingOccurrences(of: "+", with: "-")
			.replacingOccurrences(of: "/", with: "_")
			.replacingOccurrences(of: "=", with: "")
	}
	
	init?(base64urlEncoded: String) {
		let paddingLength = 4 - base64urlEncoded.count % 4
		let padding = (paddingLength < 4) ? String(repeating: "=", count: paddingLength) : ""
		let base64EncodedString = base64urlEncoded
			.replacingOccurrences(of: "-", with: "+")
			.replacingOccurrences(of: "_", with: "/")
			+ padding
		self.init(base64Encoded: base64EncodedString)
	}
}
