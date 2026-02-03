using System.Runtime.InteropServices;

namespace SharpMiniFilter.Driver;

public static class CommonMessages
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct AUTH_HEADER
    {
        public uint Version;
        public ulong Timestamp100ns;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Nonce;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] Hmac;
    }
    
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct AUTH_PACKET_NOPAYLOAD
    {
        public AUTH_HEADER Auth;
    }
}