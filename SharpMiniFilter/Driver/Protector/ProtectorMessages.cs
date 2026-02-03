using System.Runtime.InteropServices;

namespace SharpMiniFilter.Driver.Protector;

public static class ProtectorMessages
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PORT_OBC_REQ_HDR
    {
        public uint Command;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PORT_OBC_BULK_HEAD
    {
        public uint Count;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PORT_OBC_BULK_RSP
    {
        public int Status;
        public uint Processed;
        public uint Added;
        public uint Duplicates;
        public uint Invalid;
    }
    
}