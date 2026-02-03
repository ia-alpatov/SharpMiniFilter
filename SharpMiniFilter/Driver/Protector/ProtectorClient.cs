using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SharpMiniFilter.Driver.Protector;

public static class ProtectorClient
{
    private static readonly object _messagesSendSync = new();

    public static bool ReplaceProtectList(IEnumerable<string> names)
    {
        try
        {
            var body = ProtectorUtils.BuildBulkNamesPayload(names, out _);
            var response =
                SendMessage<ProtectorMessages.PORT_OBC_BULK_RSP>(Constants.PORT_CMD_OBC_REPLACE_PROTECT, body);
            return response.Status == 0;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(e);
            return false;
        }
    }

    public static bool ReplaceRejectList(IEnumerable<string> names)
    {
        try
        {
            var body = ProtectorUtils.BuildBulkNamesPayload(names, out _);
            var response = SendMessage<ProtectorMessages.PORT_OBC_BULK_RSP>(Constants.PORT_CMD_OBC_REPLACE_REJECT, body);
            return response.Status == 0;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(e);
            return false;
        }
    }
    
    private static T SendMessage<T>(uint command, byte[] body) where T : struct
    {
        lock (_messagesSendSync)
        {
            using var connectionHandle = ConnectAndAuthWithRetry(Constants.PROTECTOR_PORT);

            int hdrSize = Unsafe.SizeOf<ProtectorMessages.PORT_OBC_REQ_HDR>();
            byte[] inb = new byte[hdrSize + body.Length];
            unsafe
            {
                fixed (byte* p = inb)
                {
                    var hdr = new ProtectorMessages.PORT_OBC_REQ_HDR { Command = command, Reserved = 0 };
                    Unsafe.WriteUnaligned(ref *p, hdr);
                    fixed (byte* b = body) Buffer.MemoryCopy(b, p + hdrSize, body.Length, body.Length);
                }
            }

            int outSize = Unsafe.SizeOf<T>();
            IntPtr inPtr = Marshal.AllocHGlobal(inb.Length);
            IntPtr outPtr = Marshal.AllocHGlobal(outSize);
            try
            {
                Marshal.Copy(inb, 0, inPtr, inb.Length);
                int hr = Native.FilterSendMessage(connectionHandle.DangerousGetHandle(), inPtr, (uint)inb.Length, outPtr,
                    (uint)outSize, out var _);
                if (hr != 0) 
                    throw new Win32Exception(hr & 0xFFFF, $"OB FilterSendMessage 0x{hr:X8}");
                return Marshal.PtrToStructure<T>(outPtr);
            }
            finally
            {
                Marshal.FreeHGlobal(inPtr);
                Marshal.FreeHGlobal(outPtr);
            }
        }
    }
    
    private static SafeFileHandle ConnectAndAuthWithRetry(string portName, int tries = 3, int delayMs = 50)
    {
        for (int i = 0; i < tries; i++)
        {
            try
            {
                return ConnectAndAuth(portName);
            }
            catch (Win32Exception ex) when ((ex.NativeErrorCode == 0x4D6)
                                            || (ex.NativeErrorCode == 0x217))
            {
                if (i == tries - 1) throw;
                Thread.Sleep(delayMs);
            }
        }

        throw new InvalidOperationException("Port unreachable");
    }
    
    private static SafeFileHandle ConnectAndAuth(string portName)
    {
        int hr = Native.FilterConnectCommunicationPort(portName, 0, IntPtr.Zero, 0, IntPtr.Zero, out var raw);
        if (hr < 0 || raw == IntPtr.Zero)
            throw new Win32Exception(hr & 0xFFFF, $"Connect {portName} 0x{hr:X8}");
        var handle = new SafeFileHandle(raw, ownsHandle: true);
        CommonUtils.PortAuth(handle);
        return handle;
    }
}