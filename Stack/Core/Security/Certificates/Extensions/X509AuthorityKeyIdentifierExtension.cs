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

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;

namespace Opc.Ua.Security.Certificates
{
    /// <summary>
    /// Stores the authority key identifier extension.
    /// </summary>
    /// <remarks>
    ///     id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
    ///     AuthorityKeyIdentifier ::= SEQUENCE {
    ///         keyIdentifier[0] KeyIdentifier           OPTIONAL,
    ///         authorityCertIssuer[1] GeneralNames            OPTIONAL,
    ///         authorityCertSerialNumber[2] CertificateSerialNumber OPTIONAL
    ///         }
    ///     KeyIdentifier::= OCTET STRING
    /// </remarks>
    public class X509AuthorityKeyIdentifierExtension : X509Extension
    {
        #region Constructors

        /// <summary>
        /// Creates an extension from ASN.1 encoded data.
        /// </summary>
        public X509AuthorityKeyIdentifierExtension(AsnEncodedData encodedExtension, bool critical)
        :
            this(encodedExtension.Oid, encodedExtension.RawData, critical)
        {
        }

        /// <summary>
        /// Creates an extension from ASN.1 encoded data.
        /// </summary>
        public X509AuthorityKeyIdentifierExtension(Oid oid, byte[] rawData, bool critical)
        :
            base(oid, rawData, critical)
        {
            Decode(rawData);
        }
        #endregion

        #region Overridden Methods
        /// <summary>
        /// Returns a formatted version of the Authority Key Identifier as a string.
        /// </summary>
        public override string Format(bool multiLine)
        {
            StringBuilder buffer = new StringBuilder();

            if (m_keyIdentifier != null && m_keyIdentifier.Length > 0)
            {
                if (buffer.Length > 0)
                {
                    if (multiLine)
                    {
                        buffer.AppendLine();
                    }
                    else
                    {
                        buffer.Append(", ");
                    }
                }

                buffer.Append(kKeyIdentifier);
                buffer.Append('=');
                buffer.Append(m_keyIdentifier.ToHexString());
            }

            if (m_issuer != null)
            {
                if (multiLine)
                {
                    buffer.AppendLine();
                }
                else
                {
                    buffer.Append(", ");
                }

                buffer.Append(kIssuer);
                buffer.Append('=');
                buffer.Append(m_issuer.Format(true));
            }

            if (m_serialNumber != null && m_serialNumber.Length > 0)
            {
                if (buffer.Length > 0)
                {
                    if (!multiLine)
                    {
                        buffer.Append(", ");
                    }
                }

                buffer.Append(kSerialNumber);
                buffer.Append('=');
                buffer.Append(m_serialNumber);
            }
            return buffer.ToString();

        }
        #endregion

        #region Public Properties
        /// <summary>
        /// The OID for a Authority Key Identifier extension.
        /// </summary>
        public const string AuthorityKeyIdentifierOid = "2.5.29.1";

        /// <summary>
        /// The alternate OID for a Authority Key Identifier extension.
        /// </summary>
        public const string AuthorityKeyIdentifier2Oid = "2.5.29.35";

        /// <summary>
        /// The identifier for the key as a little endian hexadecimal string.
        /// </summary>
        public string KeyIdentifier => m_keyIdentifier.ToHexString();

        /// <summary>
        /// The identifier for the key as a byte array.
        /// </summary>
        public byte[] GetKeyIdentifier() => m_keyIdentifier;

        /// <summary>
        /// A list of distinguished names for the issuer.
        /// </summary>
        public X500DistinguishedName Issuer => m_issuer;

        /// <summary>
        /// A list of distinguished names for the issuer.
        /// </summary>
        /// <summary>
        /// The identifier for the key.
        /// </summary>
        public string KeyId
        {
            get { return m_keyId; }
        }

        /// <summary>
        /// A list of names for the issuer.
        /// </summary>
        public string[] AuthorityNames
        {
            get { return m_authorityNames; }
        }

        /// <summary>
        /// The serial number for the key.
        /// </summary>
        public string SerialNumber
        {
            get { return m_serialNumber; }
        }
        #endregion

        #region Private Methods

        private void Decode(byte[] data)
        {

            #region Legacy Property holders
            byte[] keyId;
            byte[] serialNumber;

            if (base.Oid.Value == AuthorityKeyIdentifierOid)
            {
                CertificateFactory.ParseAuthorityKeyIdentifierExtension(
                    data,
                    out keyId,
                    out m_authorityNames,
                    out serialNumber);
            }
            else
            {
                CertificateFactory.ParseAuthorityKeyIdentifierExtension2(
                    data,
                    out keyId,
                    out m_authorityNames,
                    out serialNumber);
            }

            m_keyId = Utils.ToHexString(keyId);
            m_serialNumber = null;

            // the serial number is a little endian integer so must convert to string in reverse order. 
            if (serialNumber != null)
            {
                StringBuilder builder = new StringBuilder(serialNumber.Length * 2);

                for (int ii = serialNumber.Length - 1; ii >= 0; ii--)
                {
                    builder.AppendFormat("{0:X2}", serialNumber[ii]);
                }

                m_serialNumber = builder.ToString();
            }

            #endregion

            if (base.Oid.Value == AuthorityKeyIdentifierOid ||
                base.Oid.Value == AuthorityKeyIdentifier2Oid)
            {
                try
                {
                    Asn1Object obj = Asn1Object.FromByteArray(data);
                    AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.GetInstance(obj);
                    if (authorityKeyIdentifier != null)
                    {
                        m_keyIdentifier = authorityKeyIdentifier.GetKeyIdentifier();
                        if (authorityKeyIdentifier.AuthorityCertIssuer != null)
                        {
                            m_issuer = new X500DistinguishedName(authorityKeyIdentifier.AuthorityCertIssuer.GetDerEncoded());
                        }
                        return;
                    }
                    else
                    {
                        throw new CryptographicException("Failed to decode the AuthorityKeyIdentifier extention; No valid data");
                    }
                }
                catch (Exception ace)
                {
                    throw new CryptographicException("Failed to decode the AuthorityKeyIdentifier extension.", ace);
                }
            }
        }
        #endregion

        #region Private Fields
        /// <summary>
        /// Authority Key Identifier extension string
        /// definitions see RFC 5280 4.2.1.1
        /// </summary>

        #region Legacy
        private string m_keyId;
        private string[] m_authorityNames;
        private string m_serialNumber;
        #endregion
        private const string kKeyIdentifier = "KeyID";
        private const string kIssuer = "Issuer";
        private const string kSerialNumber = "SerialNumber";
        private const string kFriendlyName = "Authority Key Identifier";
        private byte[] m_keyIdentifier;
        private X500DistinguishedName m_issuer;
        #endregion
    }
}
