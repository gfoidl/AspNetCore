// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;

namespace Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http3.QPack
{
    internal readonly struct HeaderField
    {
        public HeaderField(Span<byte> name, Span<byte> value)
        {
            Name = name.ToArray();
            Value = value.ToArray();
        }

        public byte[] Name { get; }

        public byte[] Value { get; }

        public int Length => GetLength(Name.Length, Value.Length);

        public static int GetLength(int nameLength, int valueLength) => nameLength + valueLength;
    }
}
