using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using SharpMiniFilter.Driver.Protector;

namespace SharpMiniFilter.Driver;

public static class CommonUtils
{
    public static void PortAuth(SafeFileHandle port)
    {
        var authHeader = BuildAuthHeader();
        var authPacket = new CommonMessages.AUTH_PACKET_NOPAYLOAD { Auth = authHeader };

        int inSize = Marshal.SizeOf<CommonMessages.AUTH_PACKET_NOPAYLOAD>();
        int outSize = 4096;
        IntPtr inPtr = Marshal.AllocHGlobal(inSize);
        IntPtr outPtr = Marshal.AllocHGlobal(outSize);
        try
        {
            Marshal.StructureToPtr(authPacket, inPtr, false);
            int sendMessageResult = Native.FilterSendMessage(port.DangerousGetHandle(), inPtr, (uint)inSize, outPtr, (uint)outSize,
                out var got);
            if (sendMessageResult != 0) 
                throw new Win32Exception(sendMessageResult & 0xFFFF, $"Auth FilterSendMessage 0x{sendMessageResult:X8}");

            string? reply = Marshal.PtrToStringUni(outPtr);
            if (string.IsNullOrEmpty(reply) || !reply.StartsWith("OK", StringComparison.Ordinal))
                throw new InvalidOperationException($"Auth failed: '{reply ?? "<null>"}'");
        }
        finally
        {
            Marshal.FreeHGlobal(inPtr);
            Marshal.FreeHGlobal(outPtr);
        }
    }
    
    private static CommonMessages.AUTH_HEADER BuildAuthHeader()
    {
        var authHeader = new CommonMessages.AUTH_HEADER
        {
            Version = Constants.AUTH_VERSION,
            Timestamp100ns = (ulong)DateTime.UtcNow.ToFileTimeUtc(),
            Nonce = new byte[16],
            Hmac = new byte[32]
        };

        RandomNumberGenerator.Fill(authHeader.Nonce);

        using (var hmac = new HMACSHA256(Constants.HmacKey))
        {
            int dataSize = sizeof(uint) + sizeof(ulong) + authHeader.Nonce.Length;
            byte[] dataToHash = new byte[dataSize];
            Buffer.BlockCopy(BitConverter.GetBytes(authHeader.Version), 0, dataToHash, 0, sizeof(uint));
            Buffer.BlockCopy(BitConverter.GetBytes(authHeader.Timestamp100ns), 0, dataToHash, sizeof(uint), sizeof(ulong));
            Buffer.BlockCopy(authHeader.Nonce, 0, dataToHash, sizeof(uint) + sizeof(ulong), authHeader.Nonce.Length);

            byte[] hash = hmac.ComputeHash(dataToHash);
            Array.Copy(hash, authHeader.Hmac, Math.Min(hash.Length, authHeader.Hmac.Length));
        }

        return authHeader;
    }
}