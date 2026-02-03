using System.Runtime.InteropServices;

namespace SharpMiniFilter.Driver;

internal static partial class Native
{
    [LibraryImport("fltlib.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial int FilterConnectCommunicationPort(string name, uint opts, IntPtr ctx, uint ctxSize,
        IntPtr sd, out IntPtr port);
    
    [LibraryImport("fltlib.dll", SetLastError = true)]
    public static partial int FilterSendMessage(
        IntPtr port,
        IntPtr inBuffer,
        uint inBufferSize,
        IntPtr outBuffer,
        uint outBufferSize,
        out uint bytesReturned);

    [LibraryImport("fltlib.dll", SetLastError = true)]
    public static partial int FilterGetMessage(IntPtr port, IntPtr replyBuffer, uint replyBufferSize,
        IntPtr overlapped);

    [LibraryImport("fltlib.dll", SetLastError = true)]
    public static partial int FilterReplyMessage(IntPtr port, IntPtr replyBuffer, uint replyBufferSize);
}