//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import NIOCore
@_implementationOnly import CNIOBoringSSL

// We can only use Security.framework to validate TLS certificates on Apple platforms.
#if canImport(Darwin)
import Dispatch
import Foundation
import Security

extension SSLConnection {
    func performSecurityFrameworkValidation(promise: EventLoopPromise<NIOSSLVerificationResult>, peerCertificates: [SecCertificate]) {
        guard case .default = self.parentContext.configuration.trustRoots ?? .default else {
            preconditionFailure("This callback should only be used if we are using the system-default trust.")
        }

        // This force-unwrap is safe as we must have decided if we're a client or a server before validation.
        let role = self.role!
        let expectedHostname = self.expectedHostname
        let tlsConfiguration = self.parentContext.configuration
        // TODO: Maybe use a @preconcurrency import for this type?
        let peerCertificates = UnsafeTransfer(peerCertificates as CFArray)

        // We create a DispatchQueue here to be called back on, as this validation may perform network activity.
        let callbackQueue = DispatchQueue(label: "io.swiftnio.ssl.validationCallbackQueue")

        // SecTrustEvaluateAsync and its cousin withError require that they are called from the same queue given to
        // them as a parameter. Thus, we async away now.
        callbackQueue.async {
            do {
                let policy = SecPolicyCreateSSL(role == .client, expectedHostname as CFString?)
                var trust: SecTrust? = nil
                var result: OSStatus
                result = SecTrustCreateWithCertificates(peerCertificates.wrappedValue, policy, &trust)
                guard result == errSecSuccess, let actualTrust = trust else {
                    throw NIOSSLError.unableToValidateCertificate
                }

                // If there are additional trust roots then we need to add them to the SecTrust as anchors.
                let additionalAnchorCertificates: [SecCertificate] = try tlsConfiguration.additionalTrustRoots.flatMap { trustRoots -> [NIOSSLCertificate] in
                    guard case .certificates(let certs) = trustRoots else {
                        preconditionFailure("This callback happens on the request path, file-based additional trust roots should be pre-loaded when creating the SSLContext.")
                    }
                    return certs
                }.map {
                    guard let secCert = SecCertificateCreateWithData(nil, Data(try $0.toDERBytes()) as CFData) else {
                        throw NIOSSLError.failedToLoadCertificate
                    }
                    return secCert
                }
                if !additionalAnchorCertificates.isEmpty {
                    guard SecTrustSetAnchorCertificates(actualTrust, additionalAnchorCertificates as CFArray) == errSecSuccess else {
                        throw NIOSSLError.failedToLoadCertificate
                    }
                    // To use additional anchors _and_ the built-in ones we must reenable the built-in ones expicitly.
                    guard SecTrustSetAnchorCertificatesOnly(actualTrust, false) == errSecSuccess else {
                        throw NIOSSLError.failedToLoadCertificate
                    }
                }

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
            } catch {
                promise.fail(error)
            }
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

extension SSLConnection {
    func getPeerCertificatesAsSecCertificate() throws -> [SecCertificate] {
        try self.withPeerCertificateChainBuffers { buffers in
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
    }
}

#endif
