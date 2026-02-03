using System.Runtime.InteropServices;

namespace SharpMiniFilter.Driver.MiniFilter;

public static class MiniFilterUtils
{
    public static unsafe void EnsureCapacity(ref int capacity, ref IntPtr pointer, int bytes)
    {
        if (capacity >= bytes) 
            return;
        pointer = pointer == IntPtr.Zero ? Marshal.AllocHGlobal(bytes) : Marshal.ReAllocHGlobal(pointer, bytes);
        capacity = bytes;
        new Span<byte>(pointer.ToPointer(), capacity).Clear();
    }
    
    public static unsafe string SafeReadString(in MiniFilterMessages.FLT_TO_USER_RAW data)
    {
        int length = 0;
        fixed (char* p = data.path)
        {
            while (length < 2048 && p[length] != '\0') length++;
            return length == 0 ? string.Empty : new string(p, 0, length);
        }
    }
}