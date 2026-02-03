using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SharpMiniFilter.Driver.MiniFilter;

public static class MiniFilterClient
{
    private static IntPtr _recv = IntPtr.Zero;
    private static int _recvCapacity = 0;
    private static IntPtr _reply = IntPtr.Zero;
    private static int _replyCapacity = 0;

    private static SafeFileHandle? _minifilterHandle = null;

    private static CancellationTokenSource? _cancellationTokenSource = null;

    public delegate void MinifilterEventHandler(MinifilterEventArgs e);
    public static event MinifilterEventHandler? DriverFilter;

   
    public static bool Connect()
    {
        _cancellationTokenSource = new CancellationTokenSource();
        
        if (!ConnectToPort()) 
            return false;
        
        Console.WriteLine($"Connected to MINIFILTER port");
        
        Task.Run(() =>
        {
            try
            {
                unsafe
                {
                    while (true)
                    {
                        _cancellationTokenSource!.Token.ThrowIfCancellationRequested();

                        int replySize = Marshal.SizeOf<MiniFilterMessages.FILTER_REPLY_HEADER>() + sizeof(int);
                        Marshal.WriteInt32(_recv, 0, replySize);

                        int getMessageResult = Native.FilterGetMessage(_minifilterHandle!.DangerousGetHandle(), _recv, (uint)_recvCapacity,
                            IntPtr.Zero);
                        
                        if (getMessageResult < 0)
                        {
                            int w32 = getMessageResult & 0xFFFF;
                            if (w32 == Constants.ERROR_INSUFFICIENT_BUFFER)
                            {
                                MiniFilterUtils.EnsureCapacity(ref _recvCapacity, ref _recv, _recvCapacity * 2);
                                continue;
                            }

                            throw new Win32Exception(w32, $"FilterGetMessage 0x{getMessageResult:X8}");
                        }

                        ref readonly MiniFilterMessages.FILTER_MESSAGE_HEADER messageHeader =
                            ref Unsafe.AsRef<MiniFilterMessages.FILTER_MESSAGE_HEADER>(_recv.ToPointer());
                        IntPtr dataPtr = IntPtr.Add(_recv, Unsafe.SizeOf<MiniFilterMessages.FILTER_MESSAGE_HEADER>());
                        ref readonly MiniFilterMessages.FLT_TO_USER_RAW data =
                            ref Unsafe.AsRef<MiniFilterMessages.FLT_TO_USER_RAW>(dataPtr.ToPointer());

                        bool blockProcess = false;
                        try
                        {
                            var pid = data.pId;
                            var path = MiniFilterUtils.SafeReadString(in data);
                            if (TryHandleMessage(messageHeader.MessageId, path, pid,
                                    out var status))
                                blockProcess = status;
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine($"Handler error: {ex.GetType().Name}: {ex.Message}");
                        }

                        int responseHeader = Marshal.SizeOf<MiniFilterMessages.FILTER_REPLY_HEADER>();
                        int total = checked((int)messageHeader.ReplyLength);
                        if (total < responseHeader) 
                            total = responseHeader;
                        MiniFilterUtils.EnsureCapacity(ref _replyCapacity, ref _reply, total);
                        new Span<byte>(_reply.ToPointer(), total).Clear();

                        Marshal.WriteInt32(_reply, 0, 0);
                        Marshal.WriteInt64(_reply, 8, unchecked((long)messageHeader.MessageId));
                        
                        if (total >= responseHeader + sizeof(int))
                            Marshal.WriteInt32(_reply, responseHeader, blockProcess ? 1 : 0);

                        int responseResult = Native.FilterReplyMessage(_minifilterHandle.DangerousGetHandle(), _reply, (uint)total);
                        if (responseResult != 0)
                            Console.WriteLine(
                                $"FilterReplyMessage 0x{responseResult:X8} ({new Win32Exception(responseResult & 0xFFFF).Message})");
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.ToString());
            }
        }, _cancellationTokenSource.Token);

        return true;
    }

    private static bool ConnectToPort()
    {
        try
        {
            int connectionResult = Native.FilterConnectCommunicationPort(
                Constants.MINIFILTER_PORT, 0, IntPtr.Zero, 0, IntPtr.Zero, out var rawMini);
            if (connectionResult < 0 || rawMini == IntPtr.Zero)
                throw new Win32Exception(connectionResult & 0xFFFF, $"Connect MiniPort 0x{connectionResult:X8}");
            
            _minifilterHandle = new SafeFileHandle(rawMini, ownsHandle: true);
            CommonUtils.PortAuth(_minifilterHandle);

            MiniFilterUtils.EnsureCapacity(ref _recvCapacity, ref _recv, 8192);
            MiniFilterUtils.EnsureCapacity(ref _replyCapacity, ref _reply, 1024);
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.ToString());
            try
            {
                _minifilterHandle?.Dispose();
            }
            catch
            {
            }

            _minifilterHandle = null;
            return false;
        }
    }
    
    public static void CloseConnection()
    {
        _cancellationTokenSource?.Cancel();
        _cancellationTokenSource = null;
        try
        {
            _minifilterHandle?.Dispose();
        }
        catch
        {
        }

        _minifilterHandle = null;

        if (_recv != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(_recv);
            _recv = IntPtr.Zero;
            _recvCapacity = 0;
        }

        if (_reply != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(_reply);
            _reply = IntPtr.Zero;
            _replyCapacity = 0;
        }
    }

    private static bool TryHandleMessage(ulong msgId, string path, uint pid, out bool result)
    {
        var handler = DriverFilter;
        var e = new MinifilterEventArgs(msgId, path, pid);

        bool isHandled = false;

        if (handler != null)
        {
            foreach (MinifilterEventHandler h in handler.GetInvocationList())
            {
                h(e);
                if (e.Handled)
                {
                    result = e.Result;
                    isHandled = true;
                }
            }
        }

        result = e.Result;
        return isHandled;
    }
    
    
  

}
