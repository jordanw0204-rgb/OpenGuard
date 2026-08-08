using Microsoft.UI.Xaml;

namespace OpenGuard.App;

public partial class App : Application
{
    public static Window Window { get; private set; } = null!;

    public App()
    {
        UnhandledException += (_, eventArgs) => LogException(eventArgs.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, eventArgs) =>
        {
            if (eventArgs.ExceptionObject is Exception exception)
            {
                LogException(exception);
            }
        };
        try
        {
            InitializeComponent();
        }
        catch (Exception exception)
        {
            LogException(exception);
            throw;
        }
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        try
        {
            Window = new MainWindow();
            Window.Activate();
        }
        catch (Exception exception)
        {
            LogException(exception);
            throw;
        }
    }

    internal static void LogException(Exception exception)
    {
        string directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "OpenGuard",
            "Logs");
        Directory.CreateDirectory(directory);
        File.AppendAllText(
            Path.Combine(directory, "ui-crash.log"),
            $"{DateTimeOffset.UtcNow:O}{Environment.NewLine}{exception}{Environment.NewLine}{Environment.NewLine}");
    }
}
