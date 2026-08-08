using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using Windows.Foundation;

namespace OpenGuard.App.Controls;

public sealed partial class ActivityGraph : UserControl
{
    private bool isLoaded;
    private bool renderQueued;

    public static readonly DependencyProperty TitleProperty = DependencyProperty.Register(
        nameof(Title), typeof(string), typeof(ActivityGraph), new PropertyMetadata(string.Empty));
    public static readonly DependencyProperty PrimaryLabelProperty = DependencyProperty.Register(
        nameof(PrimaryLabel), typeof(string), typeof(ActivityGraph), new PropertyMetadata(string.Empty));
    public static readonly DependencyProperty SecondaryLabelProperty = DependencyProperty.Register(
        nameof(SecondaryLabel), typeof(string), typeof(ActivityGraph), new PropertyMetadata(string.Empty));
    public static readonly DependencyProperty PrimaryValueTextProperty = DependencyProperty.Register(
        nameof(PrimaryValueText), typeof(string), typeof(ActivityGraph), new PropertyMetadata(string.Empty));
    public static readonly DependencyProperty SecondaryValueTextProperty = DependencyProperty.Register(
        nameof(SecondaryValueText), typeof(string), typeof(ActivityGraph), new PropertyMetadata(string.Empty));
    public static readonly DependencyProperty PrimaryStrokeProperty = DependencyProperty.Register(
        nameof(PrimaryStroke), typeof(Brush), typeof(ActivityGraph), new PropertyMetadata(null, OnVisualPropertyChanged));
    public static readonly DependencyProperty SecondaryStrokeProperty = DependencyProperty.Register(
        nameof(SecondaryStroke), typeof(Brush), typeof(ActivityGraph), new PropertyMetadata(null, OnVisualPropertyChanged));
    public static readonly DependencyProperty PrimaryValuesProperty = DependencyProperty.Register(
        nameof(PrimaryValues), typeof(ObservableCollection<double>), typeof(ActivityGraph), new PropertyMetadata(null, OnSeriesPropertyChanged));
    public static readonly DependencyProperty SecondaryValuesProperty = DependencyProperty.Register(
        nameof(SecondaryValues), typeof(ObservableCollection<double>), typeof(ActivityGraph), new PropertyMetadata(null, OnSeriesPropertyChanged));
    public static readonly DependencyProperty SharedScaleProperty = DependencyProperty.Register(
        nameof(SharedScale), typeof(bool), typeof(ActivityGraph), new PropertyMetadata(true, OnVisualPropertyChanged));

    public ActivityGraph()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    public string Title { get => (string)GetValue(TitleProperty); set => SetValue(TitleProperty, value); }

    public string PrimaryLabel { get => (string)GetValue(PrimaryLabelProperty); set => SetValue(PrimaryLabelProperty, value); }

    public string SecondaryLabel { get => (string)GetValue(SecondaryLabelProperty); set => SetValue(SecondaryLabelProperty, value); }

    public string PrimaryValueText { get => (string)GetValue(PrimaryValueTextProperty); set => SetValue(PrimaryValueTextProperty, value); }

    public string SecondaryValueText { get => (string)GetValue(SecondaryValueTextProperty); set => SetValue(SecondaryValueTextProperty, value); }

    public Brush? PrimaryStroke { get => (Brush?)GetValue(PrimaryStrokeProperty); set => SetValue(PrimaryStrokeProperty, value); }

    public Brush? SecondaryStroke { get => (Brush?)GetValue(SecondaryStrokeProperty); set => SetValue(SecondaryStrokeProperty, value); }

    public ObservableCollection<double>? PrimaryValues
    {
        get => (ObservableCollection<double>?)GetValue(PrimaryValuesProperty);
        set => SetValue(PrimaryValuesProperty, value);
    }

    public ObservableCollection<double>? SecondaryValues
    {
        get => (ObservableCollection<double>?)GetValue(SecondaryValuesProperty);
        set => SetValue(SecondaryValuesProperty, value);
    }

    public bool SharedScale { get => (bool)GetValue(SharedScaleProperty); set => SetValue(SharedScaleProperty, value); }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        isLoaded = true;
        Attach(PrimaryValues);
        Attach(SecondaryValues);
        ScheduleRender();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        isLoaded = false;
        renderQueued = false;
        Detach(PrimaryValues);
        Detach(SecondaryValues);
    }

    private void OnPlotSizeChanged(object sender, SizeChangedEventArgs e) => ScheduleRender();

    private static void OnSeriesPropertyChanged(DependencyObject sender, DependencyPropertyChangedEventArgs args)
    {
        ActivityGraph graph = (ActivityGraph)sender;
        if (graph.isLoaded)
        {
            graph.Detach(args.OldValue as ObservableCollection<double>);
            graph.Attach(args.NewValue as ObservableCollection<double>);
        }
        graph.ScheduleRender();
    }

    private static void OnVisualPropertyChanged(DependencyObject sender, DependencyPropertyChangedEventArgs args) =>
        ((ActivityGraph)sender).ScheduleRender();

    private void Attach(ObservableCollection<double>? values)
    {
        if (values is not null)
        {
            values.CollectionChanged -= OnCollectionChanged;
            values.CollectionChanged += OnCollectionChanged;
        }
    }

    private void Detach(ObservableCollection<double>? values)
    {
        if (values is not null)
        {
            values.CollectionChanged -= OnCollectionChanged;
        }
    }

    private void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e) => ScheduleRender();

    private void ScheduleRender()
    {
        if (!isLoaded || renderQueued)
        {
            return;
        }
        renderQueued = true;
        if (!DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () =>
            {
                renderQueued = false;
                if (isLoaded)
                {
                    RenderChart();
                }
            }))
        {
            renderQueued = false;
        }
    }

    private void RenderChart()
    {
        if (PlotCanvas is null || PlotCanvas.ActualWidth <= 1 || PlotCanvas.ActualHeight <= 1)
        {
            return;
        }
        PlotCanvas.Children.Clear();
        Brush gridBrush = (Brush)Application.Current.Resources["OpenGuardBorderBrush"];
        for (int index = 0; index < 4; index++)
        {
            double y = index * PlotCanvas.ActualHeight / 3;
            PlotCanvas.Children.Add(new Line
            {
                X1 = 0,
                X2 = PlotCanvas.ActualWidth,
                Y1 = y,
                Y2 = y,
                Stroke = gridBrush,
                StrokeThickness = 1,
                Opacity = index is 0 or 3 ? 0.75 : 0.42,
            });
        }

        IReadOnlyList<double> primary = PrimaryValues?.ToArray() ?? [];
        IReadOnlyList<double> secondary = SecondaryValues?.ToArray() ?? [];
        double sharedMaximum = Math.Max(Maximum(primary), Maximum(secondary));
        DrawSeries(primary, PrimaryStroke, SharedScale ? sharedMaximum : Maximum(primary));
        DrawSeries(secondary, SecondaryStroke, SharedScale ? sharedMaximum : Maximum(secondary));
    }

    private void DrawSeries(IReadOnlyList<double> values, Brush? stroke, double maximum)
    {
        if (stroke is null || values.Count == 0)
        {
            return;
        }
        maximum = Math.Max(maximum * 1.08, 1);
        double width = PlotCanvas.ActualWidth;
        double height = PlotCanvas.ActualHeight;
        PointCollection linePoints = [];
        for (int index = 0; index < values.Count; index++)
        {
            double x = values.Count == 1 ? width : index * width / (values.Count - 1);
            double y = height - 4 - (Math.Clamp(values[index], 0, maximum) / maximum * (height - 8));
            linePoints.Add(new Point(x, y));
        }
        PointCollection areaPoints = [new Point(linePoints[0].X, height), .. linePoints, new Point(linePoints[^1].X, height)];
        PlotCanvas.Children.Add(new Polygon
        {
            Points = areaPoints,
            Fill = stroke,
            Opacity = 0.055,
        });
        PlotCanvas.Children.Add(new Polyline
        {
            Points = linePoints,
            Stroke = stroke,
            StrokeThickness = 2,
            StrokeLineJoin = PenLineJoin.Round,
        });
    }

    private static double Maximum(IReadOnlyList<double> values) =>
        values.Count == 0 ? 0 : values.Max();
}
