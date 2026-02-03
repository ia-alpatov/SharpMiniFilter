using System;
using System.Diagnostics;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using SharpMiniFilter.Driver.MiniFilter;
using SharpMiniFilter.Driver.Protector;

namespace SharpMiniFilter.Protected;

public partial class MainWindow : Window
{
    private bool allowClose = false;
    
    public MainWindow()
    {
        InitializeComponent();
        this.Closing += (sender, args) =>
        {
            args.Cancel = !allowClose;

            if (!args.Cancel)
            {
                ProtectorClient.ReplaceProtectList(Array.Empty<string>());
                ProtectorClient.ReplaceRejectList(Array.Empty<string>());
                MiniFilterClient.CloseConnection();
                MiniFilterClient.DriverFilter -= DriverClientOnDriverFilter;
            }
        };
        
        MiniFilterClient.DriverFilter += DriverClientOnDriverFilter;
        
        if (MiniFilterClient.Connect())
        {
            ProtectorClient.ReplaceProtectList(new[] { $"PID:{Process.GetCurrentProcess().Id}" });
            ProtectorClient.ReplaceRejectList(new[] {  "*cmd.exe" });
            
            Log_TextBox.Text += "Added current process to protection list." + Environment.NewLine;
            Log_TextBox.Text += "Added cmd.exe to reject list." + Environment.NewLine;
        }
        else
        {
            Log_TextBox.Text += "Connection to driver failed." + Environment.NewLine;
            MiniFilterClient.DriverFilter -= DriverClientOnDriverFilter;
        }
    }

    private void DriverClientOnDriverFilter(MinifilterEventArgs e)
    {
        Dispatcher.UIThread.Invoke(() =>
        {
            if (e.Path.Contains("test.txt"))
            {
                if (!Process.GetProcessById((int)e.ProcessId).ProcessName.ToLower().Contains("notepad"))
                {
                    e.SetHandled(true);
                    Log_TextBox.Text += "Minifilter: test.txt blocked" + Environment.NewLine;
                }
                else
                {
                    e.SetHandled(false);
                    Log_TextBox.Text += "Minifilter: test.txt not blocked for notepad.exe" + Environment.NewLine;
                }
            }
        });
    }

    private void Button_OnClick(object? sender, RoutedEventArgs e)
    {
        allowClose = true;
        this.Close();
    }
}