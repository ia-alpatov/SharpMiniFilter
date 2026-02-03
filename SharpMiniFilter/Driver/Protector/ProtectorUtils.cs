using System.Runtime.CompilerServices;
using System.Text;

namespace SharpMiniFilter.Driver.Protector;

public static class ProtectorUtils
{
    public static byte[] BuildBulkNamesPayload(IEnumerable<string> names, out uint count)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<string>();
        
        foreach (var n in names)
        {
            if (string.IsNullOrWhiteSpace(n)) 
                continue;
            
            var baseName = NormalizeExeName(n);
            
            if (seen.Add(baseName)) 
                list.Add(baseName);
        }

        count = (uint)list.Count;

        var encoding = Encoding.Unicode;
        int stringsBytes = 0;
        
        foreach (var s in list)
            stringsBytes = checked(stringsBytes + encoding.GetByteCount(s) + 2);

        int size = Unsafe.SizeOf<ProtectorMessages.PORT_OBC_BULK_HEAD>() + stringsBytes;
        byte[] buf = new byte[size];

        unsafe
        {
            fixed (byte* p = buf)
            {
                byte* cur = p;
                Unsafe.WriteUnaligned(ref *cur, new ProtectorMessages.PORT_OBC_BULK_HEAD { Count = count });
                cur += Unsafe.SizeOf<ProtectorMessages.PORT_OBC_BULK_HEAD>();

                foreach (var s in list)
                {
                    int wrote = encoding.GetBytes(s.AsSpan(), new Span<byte>(cur, encoding.GetByteCount(s)));
                    cur += wrote;
                    *(char*)cur = '\0';
                    cur += 2;
                }
            }
        }

        return buf;
    }
    
    private static string NormalizeExeName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) 
            throw new ArgumentException("Empty name");
        var baseName = Path.GetFileName(name.Trim());
        if (baseName.Length > Constants.NAME_SIZE) 
            baseName = baseName.Substring(0, Constants.NAME_SIZE);
        return baseName;
    }
}