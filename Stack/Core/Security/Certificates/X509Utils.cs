/* Copyright (c) 1996-2022 The OPC Foundation. All rights reserved.
   The source code in this file is covered under a dual-license scenario:
     - RCL: for OPC Foundation Corporate Members in good-standing
     - GPL V2: everybody else
   RCL license terms accompanied with this source code. See http://opcfoundation.org/License/RCL/1.00/
   GNU General Public License as published by the Free Software Foundation;
   version 2 of the License are accompanied with this source code. See http://opcfoundation.org/License/GPLv2
   This source code is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/


using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Opc.Ua
{
    /// <summary>
    /// Utility functions for X509 certificates.
    /// </summary>
    public static class X509Utils
    {
        /// <summary>
        /// Determines whether the certificate is allowed to be an issuer.
        /// </summary>
        public static bool IsIssuerAllowed(X509Certificate2 certificate)
        {
            X509BasicConstraintsExtension constraints = FindBasicConstraints(certificate);

            if (constraints != null)
            {
                return constraints.CertificateAuthority;
            }

            return false;
        }

        /// <summary>
        /// Determines whether the certificate is issued by a Certificate Authority.
        /// </summary>
        public static bool IsCertificateAuthority(X509Certificate2 certificate)
        {
            var constraints = FindBasicConstraints(certificate);
            if (constraints != null)
            {
                return constraints.CertificateAuthority;
            }
            return false;
        }

        /// <summary>
        /// Return the key usage flags of a certificate.
        /// </summary>
        public static X509KeyUsageFlags GetKeyUsage(X509Certificate2 cert)
        {
            var allFlags = X509KeyUsageFlags.None;
            foreach (X509KeyUsageExtension ext in cert.Extensions.OfType<X509KeyUsageExtension>())
            {
                allFlags |= ext.KeyUsages;
            }
            return allFlags;
        }

        /// <summary>
        /// Check for self signed certificate if there is match of the Subject/Issuer.
        /// </summary>
        /// <param name="certificate">The certificate to test.</param>
        /// <returns>True if self signed.</returns>
        public static bool IsSelfSigned(X509Certificate2 certificate)
        {
            return X509Utils.CompareDistinguishedName(certificate.SubjectName, certificate.IssuerName);
        }

        /// <summary>
        /// Compares two distinguished names.
        /// </summary>
        public static bool CompareDistinguishedName(X500DistinguishedName name1, X500DistinguishedName name2)
        {
            // check for simple binary equality.
            return Utils.IsEqual(name1.RawData, name2.RawData);
        }

        /// <summary>
        /// Compares two distinguished names as strings.
        /// </summary>
        /// <remarks>
        /// Where possible, distinguished names should be compared
        /// by using the <see cref="X500DistinguishedName"/> version.
        /// </remarks>
        public static bool CompareDistinguishedName(string name1, string name2)
        {
            // check for simple equality.
            if (String.Equals(name1, name2, StringComparison.Ordinal))
            {
                return true;
            }

            // parse the names.
            List<string> fields1 = ParseDistinguishedName(name1);
            List<string> fields2 = ParseDistinguishedName(name2);

            // can't be equal if the number of fields is different.
            if (fields1.Count != fields2.Count)
            {
                return false;
            }

            return CompareDistinguishedNameFields(fields1, fields2);
        }

        /// <summary>
        /// Compares string fields of two distinguished names.
        /// </summary>
        private static bool CompareDistinguishedNameFields(IList<string> fields1, IList<string> fields2)
        {
            // compare each.
            for (int ii = 0; ii < fields1.Count; ii++)
            {
                var comparison = StringComparison.Ordinal;
                if (fields1[ii].StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                {
                    // DC hostnames may have different case
                    comparison = StringComparison.OrdinalIgnoreCase;
                }
                if (!String.Equals(fields1[ii], fields2[ii], comparison))
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Compares two distinguished names.
        /// </summary>
        public static bool CompareDistinguishedName(X509Certificate2 certificate, List<string> parsedName)
        {
            // can't compare if the number of fields is 0.
            if (parsedName.Count == 0)
            {
                return false;
            }

            // parse the names.
            List<string> certificateName = ParseDistinguishedName(certificate.Subject);

            // can't be equal if the number of fields is different.
            if (parsedName.Count != certificateName.Count)
            {
                return false;
            }

            return CompareDistinguishedNameFields(parsedName, certificateName);
        }

        /// <summary>
        /// Parses a distingushed name.
        /// </summary>
        public static List<string> ParseDistinguishedName(string name)
        {
            List<string> fields = new List<string>();

            if (String.IsNullOrEmpty(name))
            {
                return fields;
            }

            // determine the delimiter used.
            char delimiter = ',';
            bool found = false;
            bool quoted = false;

            for (int ii = name.Length - 1; ii >= 0; ii--)
            {
                char ch = name[ii];

                if (ch == '"')
                {
                    quoted = !quoted;
                    continue;
                }

                if (!quoted && ch == '=')
                {
                    ii--;

                    while (ii >= 0 && Char.IsWhiteSpace(name[ii])) ii--;
                    while (ii >= 0 && (Char.IsLetterOrDigit(name[ii]) || name[ii] == '.')) ii--;
                    while (ii >= 0 && Char.IsWhiteSpace(name[ii])) ii--;

                    if (ii >= 0)
                    {
                        delimiter = name[ii];
                    }

                    break;
                }
            }

            StringBuilder buffer = new StringBuilder();

            string key = null;
            string value = null;
            found = false;

            for (int ii = 0; ii < name.Length; ii++)
            {
                while (ii < name.Length && Char.IsWhiteSpace(name[ii])) ii++;

                if (ii >= name.Length)
                {
                    break;
                }

                char ch = name[ii];

                if (found)
                {
                    char end = delimiter;

                    if (ii < name.Length && name[ii] == '"')
                    {
                        ii++;
                        end = '"';
                    }

                    while (ii < name.Length)
                    {
                        ch = name[ii];

                        if (ch == end)
                        {
                            while (ii < name.Length && name[ii] != delimiter) ii++;
                            break;
                        }

                        buffer.Append(ch);
                        ii++;
                    }

                    value = buffer.ToString().TrimEnd();
                    found = false;

                    buffer.Length = 0;
                    buffer.Append(key);
                    buffer.Append('=');

                    if (value.IndexOfAny(new char[] { '/', ',', '=' }) != -1)
                    {
                        if (value.Length > 0 && value[0] != '"')
                        {
                            buffer.Append('"');
                        }

                        buffer.Append(value);

                        if (value.Length > 0 && value[value.Length - 1] != '"')
                        {
                            buffer.Append('"');
                        }
                    }
                    else
                    {
                        buffer.Append(value);
                    }

                    fields.Add(buffer.ToString());
                    buffer.Length = 0;
                }

                else
                {
                    while (ii < name.Length)
                    {
                        ch = name[ii];

                        if (ch == '=')
                        {
                            break;
                        }

                        buffer.Append(ch);
                        ii++;
                    }

                    key = buffer.ToString().TrimEnd().ToUpperInvariant();
                    buffer.Length = 0;
                    found = true;
                }
            }

            return fields;
        }

        ///// <summary>
        ///// Returns the basic constraints identifier in the certificate.
        ///// </summary>
        private static X509BasicConstraintsExtension FindBasicConstraints(X509Certificate2 certificate)
        {
            for (int ii = 0; ii < certificate.Extensions.Count; ii++)
            {
                X509BasicConstraintsExtension extension = certificate.Extensions[ii] as X509BasicConstraintsExtension;

                if (extension != null)
                {
                    return extension;
                }
            }

            return null;
        }
    }
}
