namespace SharpMiniFilter.Driver.MiniFilter;

public sealed class MinifilterEventArgs : EventArgs
{
    public ulong MessageId { get; }
    public string Path { get; }
    public uint ProcessId { get; }

    public bool Handled { get; private set; }
    public bool Result { get; private set; }

    public MinifilterEventArgs(ulong msgId, string path, uint pid)
    {
        MessageId = msgId;
        Path = path;
        ProcessId = pid;
    }

    public bool SetHandled(bool result)
    {
        Handled = true;
        Result = result;
        return true;
    }
}