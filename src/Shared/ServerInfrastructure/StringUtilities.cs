// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Text;

#nullable enable

namespace Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Infrastructure;

internal static class StringUtilities
{
    private static readonly SpanAction<char, IntPtr> s_getAsciiOrUTF8StringNonNullCharacters = GetAsciiStringNonNullCharactersWithMarker;
    private static readonly SpanAction<char, IntPtr> s_getAsciiStringNonNullCharacters = GetAsciiStringNonNullCharacters;
    private static readonly SpanAction<char, IntPtr> s_getLatin1StringNonNullCharacters = GetLatin1StringNonNullCharacters;
    private static readonly SpanAction<char, (string? str, char separator, uint number)> s_populateSpanWithHexSuffix = PopulateSpanWithHexSuffix;

    public static unsafe string GetAsciiOrUTF8StringNonNullCharacters(this ReadOnlySpan<byte> span, Encoding defaultEncoding)
    {
        if (span.IsEmpty)
        {
            return string.Empty;
        }

        fixed (byte* source = &MemoryMarshal.GetReference(span))
        {
            var resultString = string.Create(span.Length, (IntPtr)source, s_getAsciiOrUTF8StringNonNullCharacters);

            // If resultString is marked, perform UTF-8 encoding
            if (resultString[0] == '\0')
            {
                // null characters are considered invalid
                if (span.IndexOf((byte)0) >= 0)
                {
                    throw new InvalidOperationException();
                }

                try
                {
                    resultString = defaultEncoding.GetString(span);
                }
                catch (DecoderFallbackException)
                {
                    throw new InvalidOperationException();
                }
            }

            return resultString;
        }
    }

    private static unsafe void GetAsciiStringNonNullCharactersWithMarker(Span<char> buffer, IntPtr state)
    {
        ReadOnlySpan<byte> source = new(state.ToPointer(), buffer.Length);

        // TODO: this check should be done in Ascii.ToUtf16 as extra mode.
        if (source.IndexOf((byte)0) >= 0)
        {
            buffer[0] = '\0';
            return;
        }

        OperationStatus status = Ascii.ToUtf16(source, buffer, out _, out _);

        if (status != OperationStatus.Done)
        {
            buffer[0] = '\0';
        }
    }

    public static unsafe string GetAsciiStringNonNullCharacters(this ReadOnlySpan<byte> span)
    {
        if (span.IsEmpty)
        {
            return string.Empty;
        }

        fixed (byte* source = &MemoryMarshal.GetReference(span))
        {
            return string.Create(span.Length, (IntPtr)source, s_getAsciiStringNonNullCharacters);
        }
    }

    private static unsafe void GetAsciiStringNonNullCharacters(Span<char> buffer, IntPtr state)
    {
        ReadOnlySpan<byte> source = new(state.ToPointer(), buffer.Length);

        // TODO: this check should be done in Ascii.ToUtf16 as extra mode.
        if (source.IndexOf((byte)0) >= 0)
        {
            throw new InvalidOperationException();
        }

        OperationStatus status = Ascii.ToUtf16(source, buffer, out _, out _);

        if (status != OperationStatus.Done)
        {
            throw new InvalidOperationException();
        }
    }

    public static unsafe string GetLatin1StringNonNullCharacters(this ReadOnlySpan<byte> span)
    {
        if (span.IsEmpty)
        {
            return string.Empty;
        }

        fixed (byte* source = &MemoryMarshal.GetReference(span))
        {
            return string.Create(span.Length, (IntPtr)source, s_getLatin1StringNonNullCharacters);
        }
    }

    private static unsafe void GetLatin1StringNonNullCharacters(Span<char> buffer, IntPtr state)
    {
        ReadOnlySpan<byte> source = new(state.ToPointer(), buffer.Length);

        // TODO: this check should be done in Ascii.ToUtf16 as extra mode.
        if (source.IndexOf((byte)0) >= 0)
        {
            throw new InvalidOperationException();
        }

        OperationStatus status = Ascii.ToUtf16(source, buffer, out int consumed, out _);

        if (status == OperationStatus.Done)
        {
            return;
        }

        // There was non-ASCII input, so process the remainder scalar.
        for (int i = consumed; i < source.Length; ++i)
        {
            byte value = source[i];

            if (value == 0)
            {
                throw new InvalidOperationException();
            }

            buffer[i] = (char)value;
        }
    }

    public static bool BytesOrdinalEqualsStringAndAscii(string previousValue, ReadOnlySpan<byte> newValue)
    {
        // previousValue is a previously materialized string which *must* have already passed validation.
        Debug.Assert(IsValidHeaderString(previousValue));

        // Method for Debug.Assert to ensure BytesOrdinalEqualsStringAndAscii
        // is not called with an unvalidated string comparitor.
        static bool IsValidHeaderString(string value)
        {
            try
            {
                if (value is null)
                {
                    return false;
                }
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetByteCount(value);
                return !value.Contains('\0');
            }
            catch (DecoderFallbackException)
            {
                return false;
            }
        }

        return Ascii.Equals(newValue, previousValue);
    }

    /// <summary>
    /// A faster version of String.Concat(<paramref name="str"/>, <paramref name="separator"/>, <paramref name="number"/>.ToString("X8"))
    /// </summary>
    /// <param name="str"></param>
    /// <param name="separator"></param>
    /// <param name="number"></param>
    /// <returns></returns>
    public static string ConcatAsHexSuffix(string str, char separator, uint number)
    {
        var length = 1 + 8;
        if (str != null)
        {
            length += str.Length;
        }

        return string.Create(length, (str, separator, number), s_populateSpanWithHexSuffix);
    }

    private static void PopulateSpanWithHexSuffix(Span<char> buffer, (string? str, char separator, uint number) tuple)
    {
        var (tupleStr, tupleSeparator, tupleNumber) = tuple;

        var i = 0;
        if (tupleStr != null)
        {
            tupleStr.AsSpan().CopyTo(buffer);
            i = tupleStr.Length;
        }

        buffer[i] = tupleSeparator;
        i++;

        if (Ssse3.IsSupported)
        {
            // The constant inline vectors are read from the data section without any additional
            // moves. See https://github.com/dotnet/runtime/issues/44115 Case 1.1 for further details.

            var lowNibbles = Ssse3.Shuffle(Vector128.CreateScalarUnsafe(tupleNumber).AsByte(), Vector128.Create(
                0xF, 0xF, 3, 0xF,
                0xF, 0xF, 2, 0xF,
                0xF, 0xF, 1, 0xF,
                0xF, 0xF, 0, 0xF
            ).AsByte());

            var highNibbles = Sse2.ShiftRightLogical(Sse2.ShiftRightLogical128BitLane(lowNibbles, 2).AsInt32(), 4).AsByte();
            var indices = Sse2.And(Sse2.Or(lowNibbles, highNibbles), Vector128.Create((byte)0xF));

            // Lookup the hex values at the positions of the indices
            var hex = Ssse3.Shuffle(Vector128.Create(
                (byte)'0', (byte)'1', (byte)'2', (byte)'3',
                (byte)'4', (byte)'5', (byte)'6', (byte)'7',
                (byte)'8', (byte)'9', (byte)'A', (byte)'B',
                (byte)'C', (byte)'D', (byte)'E', (byte)'F'
            ), indices);

            // The high bytes (0x00) of the chars have also been converted to ascii hex '0', so clear them out.
            hex = Sse2.And(hex, Vector128.Create((ushort)0xFF).AsByte());

            // This generates much more efficient asm than fixing the buffer and using
            // Sse2.Store((byte*)(p + i), chars.AsByte());
            Unsafe.WriteUnaligned(
                ref Unsafe.As<char, byte>(
                    ref Unsafe.Add(ref MemoryMarshal.GetReference(buffer), i)),
                hex);
        }
        else
        {
            var number = (int)tupleNumber;
            // Slice the buffer so we can use constant offsets in a backwards order
            // and the highest index [7] will eliminate the bounds checks for all the lower indicies.
            buffer = buffer.Slice(i);

            // This must be explicity typed as ReadOnlySpan<byte>
            // This then becomes a non-allocating mapping to the data section of the assembly.
            // If it is a var, Span<byte> or byte[], it allocates the byte array per call.
            ReadOnlySpan<byte> hexEncodeMap = "0123456789ABCDEF"u8;
            // Note: this only works with byte due to endian ambiguity for other types,
            // hence the later (char) casts

            buffer[7] = (char)hexEncodeMap[number & 0xF];
            buffer[6] = (char)hexEncodeMap[(number >> 4) & 0xF];
            buffer[5] = (char)hexEncodeMap[(number >> 8) & 0xF];
            buffer[4] = (char)hexEncodeMap[(number >> 12) & 0xF];
            buffer[3] = (char)hexEncodeMap[(number >> 16) & 0xF];
            buffer[2] = (char)hexEncodeMap[(number >> 20) & 0xF];
            buffer[1] = (char)hexEncodeMap[(number >> 24) & 0xF];
            buffer[0] = (char)hexEncodeMap[(number >> 28) & 0xF];
        }
    }
}
