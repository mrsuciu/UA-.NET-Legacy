/* ========================================================================
 * Copyright (c) 2005-2020 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 * 
// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if !NETSTANDARD2_1 && !NET472_OR_GREATER && !NET5_0_OR_GREATER

// This source code is intentionally copied and addapted from the .NET core runtime to close
// a gap in the .NET 4.5.1 Framework and the later implementations.
// original code is located here:
// https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/RSASignaturePadding.cs
 * ======================================================================*/

namespace Opc.Ua.Security.Certificates.Common
{
    /// <summary>
    /// Specifies the padding mode to use with RSA signature creation or verification operations.
    /// </summary>
    public enum RSASignaturePaddingMode
    {
        /// <summary>
        /// PKCS #1 v1.5.
        /// </summary>
        /// <remarks>
        /// This corresponds to the RSASSA-PKCS1-v1.5 signature scheme of the PKCS #1 RSA Encryption Standard.
        /// It is supported for compatibility with existing applications.
        /// </remarks>
        Pkcs1,

        /// <summary>
        /// Probabilistic Signature Scheme.
        /// </summary>
        /// <remarks>
        /// This corresponds to the RSASSA-PKCS1-v1.5 signature scheme of the PKCS #1 RSA Encryption Standard.
        /// It is recommended for new applications.
        /// </remarks>
        Pss,
    }
}
