//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import NIO

#if compiler(>=5.1)
@_implementationOnly import CNIOBoringSSL
#else
import CNIOBoringSSL
#endif

// We can only use Security.framework to validate TLS certificates on Apple platforms.
#if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
import Dispatch
import Foundation
import Security

extension SSLConnection {
    func performSecurityFrameworkValidation(promise: EventLoopPromise<NIOSSLVerificationResult>) {
        do {
            // Ok, time to kick off a validation. Let's get some certificate buffers.
            let certificates: [SecCertificate] = try self.withPeerCertificateChainBuffers { buffers in
                guard let buffers = buffers else {
                    throw NIOSSLError.unableToValidateCertificate
                }

                return try buffers.map { buffer in
                    let data = Data(bytes: buffer.baseAddress!, count: buffer.count)
                    guard let cert = SecCertificateCreateWithData(nil, data as CFData) else {
                        throw NIOSSLError.unableToValidateCertificate
                    }
                    return cert
                }
            }

            // This force-unwrap is safe as we must have decided if we're a client or a server before validation.
            var trust: SecTrust? = nil
            var result: OSStatus
            let policy = SecPolicyCreateSSL(self.role! == .client, self.expectedHostname as CFString?)
            result = SecTrustCreateWithCertificates(certificates as CFArray, policy, &trust)
            guard result == errSecSuccess, let actualTrust = trust else {
                throw NIOSSLError.unableToValidateCertificate
            }

            // We create a DispatchQueue here to be called back on, as this validation may perform network activity.
            let callbackQueue = DispatchQueue(label: "io.swiftnio.ssl.validationCallbackQueue")

            // SecTrustEvaluateAsync and its cousin withError require that they are called from the same queue given to
            // them as a parameter. Thus, we async away now.
            callbackQueue.async {
                let result: OSStatus

                if #available(iOS 13, macOS 10.15, tvOS 13, watchOS 6, *) {
                    result = SecTrustEvaluateAsyncWithError(actualTrust, callbackQueue) { (_, valid, _) in
                        promise.succeed(valid ? .certificateVerified : .failed)
                    }
                } else {
                    result = SecTrustEvaluateAsync(actualTrust, callbackQueue) { (_, result) in
                        promise.completeWith(result)
                    }
                }

                if result != errSecSuccess {
                    promise.fail(NIOSSLError.unableToValidateCertificate)
                }
            }
        } catch {
            promise.fail(error)
        }
    }
}

extension EventLoopPromise where Value == NIOSSLVerificationResult {
    fileprivate func completeWith(_ result: SecTrustResultType) {
        switch result {
        case .proceed, .unspecified:
            // These two cases mean we have successfully validated the certificate. We're done!
            self.succeed(.certificateVerified)
        default:
            // Oops, we failed.
            self.succeed(.failed)
        }
    }
}

#endif
