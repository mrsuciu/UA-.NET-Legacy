/* ========================================================================
 * Copyright (c) 2005-2020 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

using Opc.Ua.Security.Certificates.Common;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Opc.Ua.Security.Certificates
{
    /// <summary>
    /// Describes the three required fields of a X509 Certificate and CRL.
    /// </summary>
    public class X509Signature
    {
        /// <summary>
        /// The field contains the ASN.1 data to be signed.
        /// </summary>
        public byte[] Tbs { get; private set; }
        /// <summary>
        /// The signature of the data.
        /// </summary>
        public byte[] Signature { get; private set; }
        /// <summary>
        /// The encoded signature algorithm that was used for signing.
        /// </summary>
        public byte[] SignatureAlgorithmIdentifier { get; private set; }
        /// <summary>
        /// The signature algorithm as Oid string.
        /// </summary>
        public string SignatureAlgorithm { get; private set; }
        /// <summary>
        /// The hash algorithm used for signing.
        /// </summary>
        public HashAlgorithmName Name { get; private set; }
        /// <summary>
        /// Initialize and decode the sequence with binary ASN.1 encoded CRL or certificate.
        /// </summary>
        /// <param name="signedBlob"></param>
        public X509Signature(byte[] signedBlob)
        {
            Decode(signedBlob);
        }

        /// <summary>
        /// Decoder for the signature sequence.
        /// </summary>
        /// <param name="crl">The encoded CRL or certificate sequence.</param>
        private void Decode(byte[] crl)
        {
            try
            {
                X509CertificateStructure x509CertificateStructure = X509CertificateStructure.GetInstance(crl);
                if (x509CertificateStructure != null)
                {
                    // Tbs encoded data
                    Tbs = x509CertificateStructure.TbsCertificate.GetEncoded();

                    // Signature Algorithm Identifier
                    SignatureAlgorithm = x509CertificateStructure.SignatureAlgorithm.Algorithm.ToString();
                    Name = Oids.GetHashAlgorithmName(SignatureAlgorithm);

                    //Signature
                    Signature = x509CertificateStructure.GetSignatureOctets();
                    return;
                }
                throw new CryptographicException("No valid data in the X509 signature.");
            }
            catch (CryptographicException ace)
            {
                throw new CryptographicException("Failed to decode the X509 signature.", ace);
            }
        }

        /// <summary>
        /// Verify the signature with the public key of the signer.
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns>true if the signature is valid.</returns>
        public bool Verify(X509Certificate2 certificate)
        {
            switch (SignatureAlgorithm)
            {
                case Oids.RsaPkcs1Sha1:
                case Oids.RsaPkcs1Sha256:
                case Oids.RsaPkcs1Sha384:
                case Oids.RsaPkcs1Sha512:
                    return VerifyForRSA(certificate, RSASignaturePadding.Pkcs1);

                case Oids.ECDsaWithSha1:
                case Oids.ECDsaWithSha256:
                case Oids.ECDsaWithSha384:
                case Oids.ECDsaWithSha512:
                    return VerifyForECDsa(certificate);

                default:
                    throw new CryptographicException("Failed to verify signature due to unknown signature algorithm.");
            }
        }

        /// <summary>
        /// Verify the signature with the RSA public key of the signer.
        /// </summary>
        private bool VerifyForRSA(X509Certificate2 certificate, RSASignaturePadding padding)
        {
            try
            {
                Org.BouncyCastle.X509.X509Certificate cert = new Org.BouncyCastle.X509.X509Certificate(certificate.RawData);
                cert.Verify(cert.GetPublicKey());
                return true;
            }
            catch (Exception e)
            {
                throw new CryptographicException("Failed to verify RSA signature.", e);
            }
        }

        /// <summary>
        /// Verify the signature with the ECC public key of the signer.
        /// </summary>
        private bool VerifyForECDsa(X509Certificate2 certificate)
        {
            try
            {
                Org.BouncyCastle.X509.X509Certificate cert = new Org.BouncyCastle.X509.X509Certificate(certificate.RawData);
                cert.Verify(cert.GetPublicKey());
                return true;
            }
            catch (Exception e)
            {
                throw new CryptographicException("Failed to verify ECD signature.", e);
            }
        }

    }
}
