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

using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;

namespace Opc.Ua.Security.Certificates
{
    /// <summary>
    /// The CRL Number extension.
    /// </summary>
    /// <remarks>
    ///    id-ce-cRLNumber OBJECT IDENTIFIER::= { id-ce 20 }
    ///         CRLNumber::= INTEGER(0..MAX)
    /// </remarks>
    public class X509CrlNumberExtension : X509Extension
    {
        #region Constructors

        /// <summary>
        /// Creates an extension from ASN.1 encoded data.
        /// </summary>
        public X509CrlNumberExtension(AsnEncodedData encodedExtension, bool critical)
            : this(encodedExtension.Oid, encodedExtension.RawData, critical)
        {
        }

        /// <summary>
        /// Creates an extension from ASN.1 encoded data.
        /// </summary>
        public X509CrlNumberExtension(Oid oid, byte[] rawData, bool critical)
        :
            base(oid, rawData, critical)
        {
            Decode(rawData);
        }
        #endregion

        #region Overridden Methods

        #endregion

        #region Public Properties
        /// <summary>
        /// The OID for a CRL Number extension.
        /// </summary>
        public const string CrlNumberOid = "2.5.29.20";

        /// <summary>
        /// Gets the CRL Number.
        /// </summary>
        /// <value>The uris.</value>
        public BigInteger CrlNumber { get; private set; }
        #endregion

        #region Private Methods

        /// <summary>
        /// Decode CRL Number.
        /// </summary>
        private void Decode(byte[] data)
        {
            if (base.Oid.Value == CrlNumberOid)
            {
                try
                {
                    Asn1StreamParser aIn = new Asn1StreamParser(data);
                    Asn1SequenceParser dataReader = (Asn1SequenceParser)aIn.ReadObject();
                    object o = dataReader.ReadObject();

                    if (o != null)
                    {
                        if (o is BigInteger bigInt)
                        {
                            CrlNumber = bigInt;
                        }
                        else
                        {
                            throw new CryptographicException("Failed to decode the CRL Number extension, not a BigInteger");
                        }
                    }
                    else
                    {
                        throw new CryptographicException("Failed to decode the CRL Number extension, decoded CrlNumber returned null");
                    }
                }
                catch (Exception ace)
                {
                    throw new CryptographicException("Failed to decode the CRL Number extension.", ace);
                }
            }
            else
            {
                throw new CryptographicException("Invalid CrlNumberOid.");
            }
        }
        #endregion

        #region Private Fields
        /// <summary>
        /// CRL Number extension string
        /// definitions see RFC 5280 5.2.3
        /// </summary>
        private const string kFriendlyName = "CRL Number";
        #endregion
    }
}
