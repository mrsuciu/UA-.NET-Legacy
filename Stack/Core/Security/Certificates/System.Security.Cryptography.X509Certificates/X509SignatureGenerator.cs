// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if !NETSTANDARD2_1 && !NET472_OR_GREATER && !NET5_0_OR_GREATER

// This source code is intentionally copied from the .NET core runtime to close
// a gap in the .NET 4.6 and the .NET Core 2.x runtime implementations.
// original code is located here:
// https://github.com/dotnet/runtime/blob/master/src/libraries/System.Security.Cryptography.X509Certificates/src/System/Security/Cryptography/X509Certificates/X509SignatureGenerator.cs
#pragma warning disable CS1591 // Suppress missing XML comments to preserve original code

using Opc.Ua.Security.Certificates.Common;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Opc.Ua.Security.Certificates
{
    public abstract class X509SignatureGenerator
    {
        private PublicKey _publicKey;

        public PublicKey PublicKey
        {
            get
            {
                if (_publicKey == null)
                {
                    _publicKey = BuildPublicKey();
                }

                return _publicKey;
            }
        }

        public abstract byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm);
        public abstract byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm);
        protected abstract PublicKey BuildPublicKey();
#if NOT_SUPPORTED
        public static X509SignatureGenerator CreateForECDsa(ECDsa key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            return new ECDsaX509SignatureGenerator(key);
        }
#endif
    }
}
#endif
