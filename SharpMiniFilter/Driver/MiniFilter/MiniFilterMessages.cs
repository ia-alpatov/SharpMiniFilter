using System.Runtime.InteropServices;

namespace SharpMiniFilter.Driver.MiniFilter;

public static class MiniFilterMessages
{
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct FILTER_MESSAGE_HEADER
    {
        public uint ReplyLength;
        public ulong MessageId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct FILTER_REPLY_HEADER
    {
        public int Status;
        public ulong MessageId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public unsafe struct FLT_TO_USER_RAW
    {
        public fixed char path[2048];
        public uint pId;
    }
}