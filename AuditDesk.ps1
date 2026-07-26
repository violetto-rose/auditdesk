$script:config = @{ Console='hide'; LargeFileThresholdMB='500'; LocalFolderLimit='50'; ProgressPollMilliseconds='250'; OpenFolderAfterExport='false' }
$configPath = Join-Path $PSScriptRoot 'AuditDesk.ini'
if (Test-Path $configPath) {
    Get-Content $configPath | ForEach-Object {
        $line=$_.Trim(); if($line -and -not $line.StartsWith(';') -and $line -match '^([^=]+)=(.*)$'){$script:config[$matches[1].Trim()]=$matches[2].Trim()}
    }
}
function Get-ConfigInt($name,$fallback) { $value=0; if([int]::TryParse([string]$script:config[$name],[ref]$value) -and $value -gt 0){return $value}; return $fallback }
function Get-ConfigBool($name,$fallback=$false) { $value=[string]$script:config[$name]; if($value -match '^(true|1|yes)$'){return $true}; if($value -match '^(false|0|no)$'){return $false}; return $fallback }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Add-Type @'
using System;
using System.Runtime.InteropServices;
namespace AuditDeskNative {
    [Flags] public enum TaskbarProgressState { NoProgress = 0, Normal = 2 }
    [ComImport, Guid("EA1AFB91-9E28-4B86-90E9-9E9F8A5EEA84"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface ITaskbarList3 {
        void HrInit(); void AddTab(IntPtr hwnd); void DeleteTab(IntPtr hwnd); void ActivateTab(IntPtr hwnd); void SetActiveAlt(IntPtr hwnd);
        void MarkFullscreenWindow(IntPtr hwnd, [MarshalAs(UnmanagedType.Bool)] bool fullscreen);
        void SetProgressValue(IntPtr hwnd, UInt64 completed, UInt64 total); void SetProgressState(IntPtr hwnd, TaskbarProgressState state);
    }
    [ComImport, Guid("56FDF344-FD6D-11d0-958A-006097C9A090")] class TaskbarList { }
    public static class TaskbarProgress {
        static ITaskbarList3 taskbar;
        public static void Init(IntPtr hwnd) { try { taskbar=(ITaskbarList3)new TaskbarList(); taskbar.HrInit(); taskbar.SetProgressState(hwnd,TaskbarProgressState.NoProgress); } catch {} }
        public static void Set(IntPtr hwnd, int value) { try { if(taskbar==null) Init(hwnd); taskbar.SetProgressState(hwnd,TaskbarProgressState.Normal); taskbar.SetProgressValue(hwnd,(UInt64)Math.Max(0,Math.Min(100,value)),100); } catch {} }
        public static void Clear(IntPtr hwnd) { try { if(taskbar!=null) taskbar.SetProgressState(hwnd,TaskbarProgressState.NoProgress); } catch {} }
    }
}
'@
if ($script:config.Console -eq 'hide') {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class AuditDeskConsole { [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow); }
'@
    [AuditDeskConsole]::ShowWindow([AuditDeskConsole]::GetConsoleWindow(), 0) | Out-Null
}

$script:checks = @(
    @{ Id='winget'; Name='Winget installed apps'; Group='Apps'; Hint='Packages visible to winget'; Run={
        $raw = @(winget list 2>$null | Where-Object { $_.Trim() -and $_ -notmatch '^[-─\s]+$' } | ForEach-Object { ($_.Trim() -replace '\s{2,}', ' | ') }); [pscustomobject]@{ summary="$($raw.Count) lines captured"; items=$raw }
    }},
    @{ Id='packages'; Name='Non-winget installed apps'; Group='Apps'; Hint='Programs & Features providers'; Run={
        $items=@(Get-Package -ErrorAction SilentlyContinue | Where-Object ProviderName -ne 'winget' | Sort-Object Name | ForEach-Object { [pscustomobject]@{ name=$_.Name; version="$($_.Version)" } }); [pscustomobject]@{summary="$($items.Count) packages found";items=$items}
    }},
    @{ Id='appx'; Name='Microsoft Store / AppX apps'; Group='Apps'; Hint='Installed AppX packages'; Run={
        $items=@(Get-AppxPackage -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { [pscustomobject]@{name=$_.Name;version="$($_.Version)"} }); [pscustomobject]@{summary="$($items.Count) AppX packages found";items=$items}
    }},
    @{ Id='programfiles'; Name='Program Files leftovers'; Group='Storage'; Hint='Sizes app folders in Program Files'; Run={
        $items=@(); @($env:ProgramFiles,${env:ProgramFiles(x86)},"$env:LOCALAPPDATA\Programs") | Where-Object { $_ -and (Test-Path $_) } | ForEach-Object { $root=$_; Get-ChildItem $root -Directory -ErrorAction SilentlyContinue | ForEach-Object { $b=(Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum; $items += [pscustomobject]@{path=$_.FullName; size_mb=[math]::Round($b/1MB,1)} } }; [pscustomobject]@{summary="$($items.Count) folders scanned";items=@($items | Sort-Object size_mb -Descending)}
    }},
    @{ Id='roaming'; Name='AppData Roaming folders'; Group='Storage'; Hint='Sizes roaming app data folders'; Run={
        $items=@(Get-ChildItem $env:APPDATA -Directory -ErrorAction SilentlyContinue | ForEach-Object { $b=(Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum; [pscustomobject]@{path=$_.FullName;size_mb=[math]::Round($b/1MB,1)} } | Sort-Object size_mb -Descending); [pscustomobject]@{summary="$($items.Count) folders logged";items=$items}
    }},
    @{ Id='local'; Name='AppData Local — top 50'; Group='Storage'; Hint='Largest local app-data folders'; Run={
        $items=@(Get-ChildItem $env:LOCALAPPDATA -Directory -ErrorAction SilentlyContinue | ForEach-Object { $b=(Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum; [pscustomobject]@{path=$_.FullName;size_mb=[math]::Round($b/1MB,1)} } | Sort-Object size_mb -Descending | Select-Object -First (Get-ConfigInt 'LocalFolderLimit' 50)); [pscustomobject]@{summary="Top $($items.Count) folders by size";items=$items}
    }},
    @{ Id='programdata'; Name='ProgramData folders'; Group='Storage'; Hint='Sizes shared application data'; Run={
        $items=@(Get-ChildItem 'C:\ProgramData' -Directory -ErrorAction SilentlyContinue | ForEach-Object { $b=(Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum; [pscustomobject]@{path=$_.FullName;size_mb=[math]::Round($b/1MB,1)} } | Sort-Object size_mb -Descending); [pscustomobject]@{summary="$($items.Count) folders logged";items=$items}
    }},
    @{ Id='startup'; Name='Startup apps (Registry)'; Group='System'; Hint='Run and RunOnce registry entries'; Run={
        $keys=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'); $items=@(); foreach($k in $keys){ if(Test-Path $k){ $p=Get-ItemProperty $k -ErrorAction SilentlyContinue; $p.PSObject.Properties | Where-Object {$_.Name -notlike 'PS*'} | ForEach-Object {$items += [pscustomobject]@{name=$_.Name;command="$($_.Value)"}}}}; [pscustomobject]@{summary="$($items.Count) startup entries found";items=$items}
    }},
    @{ Id='tasks'; Name='Scheduled tasks (non-Microsoft)'; Group='System'; Hint='Tasks outside Windows task folders'; Run={
        $items=@(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object TaskPath -notlike '\Microsoft\*' | Sort-Object TaskName | ForEach-Object {[pscustomobject]@{name=$_.TaskName;path=$_.TaskPath;state="$($_.State)"}}); [pscustomobject]@{summary="$($items.Count) non-Microsoft tasks found";items=$items}
    }},
    @{ Id='services'; Name='Running non-system services'; Group='System'; Hint='Running services excluding Windows / Microsoft'; Run={
        $items=@(Get-Service -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running' -and $_.StartType -ne 'Disabled' -and $_.ServiceName -notlike 'wm*' -and $_.DisplayName -notlike 'Windows*' -and $_.DisplayName -notlike 'Microsoft*'} | Sort-Object DisplayName | ForEach-Object {[pscustomobject]@{name=$_.DisplayName;service=$_.ServiceName;start_type="$($_.StartType)"}}); [pscustomobject]@{summary="$($items.Count) services found";items=$items}
    }},
    @{ Id='largefiles'; Name='Large files in user folder'; Group='Storage'; Hint='Files above 500 MB — slow'; Run={
        $threshold=Get-ConfigInt 'LargeFileThresholdMB' 500; $items=@(Get-ChildItem $env:USERPROFILE -Recurse -File -ErrorAction SilentlyContinue | Where-Object Length -gt ($threshold*1MB) | Sort-Object Length -Descending | ForEach-Object {[pscustomobject]@{path=$_.FullName;size_gb=[math]::Round($_.Length/1GB,2)}}); [pscustomobject]@{summary="$($items.Count) files above $threshold MB";items=$items}
    }},
    @{ Id='temp'; Name='Temp folder sizes'; Group='Storage'; Hint='User, Windows, and OneDrive temp folders'; Run={
        $items=@($env:TEMP,'C:\Windows\Temp','C:\OneDriveTemp' | Where-Object {Test-Path $_} | ForEach-Object {$b=(Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum;[pscustomobject]@{path=$_;size_mb=[math]::Round($b/1MB,1)}}); [pscustomobject]@{summary="$($items.Count) temp folders measured";items=$items}
    }},
    @{ Id='disk'; Name='Disk usage summary'; Group='System'; Hint='C: free, used, and total capacity'; Run={
        $d=Get-PSDrive C; $items=@([pscustomobject]@{drive='C:';free_gb=[math]::Round($d.Free/1GB,2);used_gb=[math]::Round($d.Used/1GB,2);total_gb=[math]::Round(($d.Free+$d.Used)/1GB,2)}); [pscustomobject]@{summary='C: drive measured';items=$items}
    }}
)

[xml]$xaml=@'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="Audit Desk" Height="760" Width="1140" MinHeight="620" MinWidth="900" Background="#101513" Foreground="#E8EEE8" WindowStartupLocation="CenterScreen">
 <Window.Resources><Style TargetType="Button"><Setter Property="Margin" Value="0,0,10,0"/><Setter Property="Padding" Value="14,8"/><Setter Property="Background" Value="#1E3028"/><Setter Property="Foreground" Value="#E8EEE8"/><Setter Property="BorderBrush" Value="#4F7E62"/><Style.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#365844"/><Setter Property="Foreground" Value="#F4FFF4"/><Setter Property="BorderBrush" Value="#9FCFA8"/></Trigger></Style.Triggers></Style><Style TargetType="CheckBox"><Setter Property="Foreground" Value="#DBE5DC"/><Setter Property="FontSize" Value="13"/></Style><Style x:Key="AuditHeader" TargetType="DataGridColumnHeader"><Setter Property="Background" Value="#22352A"/><Setter Property="Foreground" Value="#E8EEE8"/><Setter Property="BorderBrush" Value="#4F7E62"/><Setter Property="FontWeight" Value="Bold"/><Setter Property="Padding" Value="8,7"/><Style.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#365844"/><Setter Property="Foreground" Value="#FFFFFF"/></Trigger></Style.Triggers></Style></Window.Resources>
 <Grid Margin="24"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
  <Grid Grid.Row="0" Margin="0,0,0,18"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><StackPanel><TextBlock Text="AUDIT DESK" FontFamily="Georgia" FontSize="30" FontWeight="Bold" Foreground="#D3E7C8"/><TextBlock Text="A read-only system inventory, shaped for fast human review and AI analysis." Foreground="#94A99A" Margin="1,5,0,0"/></StackPanel><Border Grid.Column="1" Background="#17231D" Padding="12,7" VerticalAlignment="Center"><TextBlock Name="StatusText" Text="READY" Foreground="#A5D6A7" FontWeight="Bold"/></Border></Grid>
  <Grid Grid.Row="1"><Grid.ColumnDefinitions><ColumnDefinition Width="285"/><ColumnDefinition Width="16"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
   <Border Background="#16201B" BorderBrush="#31463A" BorderThickness="1" Padding="14"><DockPanel><StackPanel DockPanel.Dock="Top"><TextBlock Text="COLLECT" FontSize="12" FontWeight="Bold" Foreground="#8BB496"/><TextBlock Name="SelectionText" Text="13 checks selected" Margin="0,4,0,12" Foreground="#93A395"/><Button Name="RunButton" Content="Run selected audit" Background="#A8D66D" Foreground="#142014" BorderBrush="#A8D66D" FontWeight="Bold"/><StackPanel Orientation="Horizontal" Margin="0,10,0,6"><Button Name="AllButton" Content="All" Padding="10,5"/><Button Name="NoneButton" Content="None" Padding="10,5"/></StackPanel></StackPanel><ListBox Name="CheckList" Background="#16201B" BorderThickness="0" Foreground="#DBE5DC"><ListBox.ItemTemplate><DataTemplate><CheckBox Content="{Binding name}" IsChecked="{Binding selected, Mode=TwoWay}" Margin="2,5"><CheckBox.ToolTip><TextBlock Text="{Binding hint}"/></CheckBox.ToolTip></CheckBox></DataTemplate></ListBox.ItemTemplate></ListBox></DockPanel></Border>
   <Border Grid.Column="2" Background="#16201B" BorderBrush="#31463A" BorderThickness="1" Padding="16"><Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions><StackPanel><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions><TextBlock Text="FINDINGS" FontWeight="Bold" Foreground="#8BB496" VerticalAlignment="Center"/><TextBlock Name="ProgressText" Grid.Column="1" Foreground="#93A395" HorizontalAlignment="Right" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/></Grid><Grid Height="22" Margin="0,9,0,0"><ProgressBar Name="AuditProgress" Minimum="0" Maximum="100" Foreground="#A8D66D" Background="#273A2E"/><TextBlock Name="ProgressPercent" Text="0%" HorizontalAlignment="Center" VerticalAlignment="Center" Foreground="#F4FFF4" FontWeight="Bold" FontSize="11"/></Grid><ProgressBar Name="ActivityBar" Height="3" Margin="0,5,0,0" IsIndeterminate="True" Visibility="Collapsed" Foreground="#75B7E3" Background="#273A2E"/></StackPanel><DataGrid Name="ResultsGrid" Grid.Row="1" Margin="0,16,0,0" AutoGenerateColumns="False" IsReadOnly="True" Background="#16201B" Foreground="#E8EEE8" RowBackground="#16201B" AlternatingRowBackground="#1A281F" BorderBrush="#31463A" ColumnHeaderStyle="{StaticResource AuditHeader}" GridLinesVisibility="Horizontal" HorizontalGridLinesBrush="#31463A"><DataGrid.Columns><DataGridTextColumn Header="Check" Binding="{Binding check}" Width="220"/><DataGridTextColumn Header="Status" Binding="{Binding status}" Width="72"/><DataGridTextColumn Header="Summary" Binding="{Binding summary}" Width="*"/><DataGridTextColumn Header="Findings" Binding="{Binding findings}" Width="80"/><DataGridTextColumn Header="Size" Binding="{Binding size}" Width="90"/></DataGrid.Columns></DataGrid></Grid></Border>
  </Grid>
  <Grid Grid.Row="2" Margin="0,16,0,0"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Text="Exports include schema, machine context, check status, and findings — no prose log parsing required." Foreground="#789080" VerticalAlignment="Center"/><StackPanel Grid.Column="1" Orientation="Horizontal"><Button Name="ExportButton" Content="Export AI JSON" IsEnabled="False"/><Button Name="OpenButton" Content="Open export folder" IsEnabled="False" Margin="0"/></StackPanel></Grid>
 </Grid>
</Window>
'@
$reader=New-Object System.Xml.XmlNodeReader $xaml; $window=[Windows.Markup.XamlReader]::Load($reader)
$script:windowHandle=[IntPtr]::Zero
$window.Add_SourceInitialized({$script:windowHandle=([Windows.Interop.WindowInteropHelper]::new($window)).Handle;[AuditDeskNative.TaskbarProgress]::Init($script:windowHandle)})
$controls=@{}; 'StatusText','SelectionText','CheckList','RunButton','AllButton','NoneButton','ResultsGrid','ProgressText','AuditProgress','ProgressPercent','ActivityBar','ExportButton','OpenButton' | ForEach-Object {$controls[$_]=$window.FindName($_)}
$view=@($script:checks | ForEach-Object {[pscustomobject]@{id=$_.Id;name=$_.Name;hint=$_.Hint;selected=$true}}); $controls.CheckList.ItemsSource=$view
$script:report=$null; $script:lastExport=$null
function Update-Selection {$n=@($view | Where-Object selected).Count; $controls.SelectionText.Text="$n checks selected"}
function Get-ResultSize($items) {
 $megabytes=0.0
 foreach($item in @($items)) { if($null -ne $item.size_mb){$megabytes+=[double]$item.size_mb} elseif($null -ne $item.size_gb){$megabytes+=[double]$item.size_gb*1024} }
 if($megabytes -ge 1024){return ('{0:N2} GB' -f ($megabytes/1024))}; if($megabytes -gt 0){return ('{0:N1} MB' -f $megabytes)}; return '—'
}
function Add-ResultRow($result) {
 $script:results += $result
 $script:rows.Add([pscustomobject]@{check=[string]($result.name);status=[string]($result.status);summary=[string]($result.summary);findings=@($result.items).Count;size=(Get-ResultSize $result.items)})
}
$script:auditTimer=New-Object System.Windows.Threading.DispatcherTimer
$script:auditTimer.Interval=[TimeSpan]::FromMilliseconds((Get-ConfigInt 'ProgressPollMilliseconds' 250))
$script:auditTimer.Add_Tick({
 if($null -eq $script:auditJob){return}
 foreach($jobMessage in @(Receive-Job -Job $script:auditJob -ErrorAction SilentlyContinue)){
   if($jobMessage.kind -eq 'started'){$controls.ActivityBar.Visibility='Visible';$controls.ProgressText.Text="$($script:results.Count) / $script:totalChecks  •  scanning $([string]($jobMessage.name))";continue}
  Add-ResultRow $jobMessage; $done=$script:results.Count; $percent=($done/$script:totalChecks)*100; $controls.AuditProgress.Value=$percent; $controls.ProgressPercent.Text=('{0:N0}%' -f $percent); [AuditDeskNative.TaskbarProgress]::Set($script:windowHandle,[int]$percent); $controls.ProgressText.Text="$done / $script:totalChecks completed" 
 }
 if($script:auditJob.State -in @('Completed','Failed','Stopped')) {
  if($script:auditJob.State -eq 'Failed' -and $script:results.Count -eq 0){Add-ResultRow ([pscustomobject]@{id='job';name='Audit job';status='error';summary=($script:auditJob.ChildJobs[0].JobStateInfo.Reason.Message);items=@()})}
  $script:auditTimer.Stop(); $controls.ActivityBar.Visibility='Collapsed'; [AuditDeskNative.TaskbarProgress]::Clear($script:windowHandle); Remove-Job -Job $script:auditJob -Force -ErrorAction SilentlyContinue; $script:auditJob=$null
  $script:report=[ordered]@{schema='audit-desk/v1';generated_at=(Get-Date).ToString('o');machine=[ordered]@{computer=$env:COMPUTERNAME;user=$env:USERNAME;windows=(Get-CimInstance Win32_OperatingSystem).Caption};checks=@($script:results)}
  $controls.AuditProgress.Value=100;$controls.ProgressPercent.Text='100%';$controls.StatusText.Text='COMPLETE';$controls.ProgressText.Text="$($script:results.Count) checks complete";$controls.RunButton.IsEnabled=$true;$controls.ExportButton.IsEnabled=$true
 }
})
$controls.AllButton.Add_Click({$view | ForEach-Object {$_.selected=$true};$controls.CheckList.Items.Refresh();Update-Selection})
$controls.NoneButton.Add_Click({$view | ForEach-Object {$_.selected=$false};$controls.CheckList.Items.Refresh();Update-Selection})
$controls.RunButton.Add_Click({
 $chosen=@($view|Where-Object selected); if(!$chosen){[System.Windows.MessageBox]::Show('Select at least one check.','Audit Desk');return}
 $work=@($chosen | ForEach-Object {$c=$script:checks|Where-Object Id -eq $_.id;[pscustomobject]@{id=$c.Id;name=$c.Name;run=$c.Run.ToString()}}); $workJson=$work|ConvertTo-Json -Depth 3 -Compress
 $script:results=@();$script:rows=New-Object 'System.Collections.ObjectModel.ObservableCollection[object]';$script:totalChecks=$work.Count
 $controls.RunButton.IsEnabled=$false;$controls.ExportButton.IsEnabled=$false;$controls.ResultsGrid.ItemsSource=$script:rows;$controls.StatusText.Text='RUNNING';$controls.ProgressText.Text="0 / $script:totalChecks completed";$controls.AuditProgress.Value=0;$controls.ProgressPercent.Text='0%';$controls.ActivityBar.Visibility='Visible';[AuditDeskNative.TaskbarProgress]::Set($script:windowHandle,0)
 $configJson=$script:config|ConvertTo-Json -Compress
 $script:auditJob=Start-Job -ArgumentList $workJson,$configJson -ScriptBlock {param($json,$configJson) $script:config=@{};($configJson|ConvertFrom-Json).PSObject.Properties|ForEach-Object {$script:config[$_.Name]="$( $_.Value )"};function Get-ConfigInt($name,$fallback) {$value=0;if([int]::TryParse([string]$script:config[$name],[ref]$value) -and $value -gt 0){return $value};return $fallback};$_c=$json|ConvertFrom-Json;foreach($check in $_c){[pscustomobject]@{kind='started';name=$check.name};try{$runner=[scriptblock]::Create([string]$check.run);$r=& $runner;[pscustomobject]@{kind='result';id=$check.id;name=$check.name;status='ok';summary=$r.summary;items=@($r.items)}}catch{[pscustomobject]@{kind='result';id=$check.id;name=$check.name;status='error';summary=$_.Exception.Message;items=@()}}}}
 $script:auditTimer.Start()
})
$controls.ExportButton.Add_Click({$dir=Join-Path $env:USERPROFILE 'Downloads\AuditDesk';New-Item $dir -ItemType Directory -Force|Out-Null;$script:lastExport=Join-Path $dir ("audit-desk_"+(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')+'.json');$script:report|ConvertTo-Json -Depth 7 -Compress|Set-Content $script:lastExport -Encoding UTF8;$controls.StatusText.Text='EXPORTED';$controls.OpenButton.IsEnabled=$true;if(Get-ConfigBool 'OpenFolderAfterExport') {Start-Process explorer.exe "/select,`"$script:lastExport`""};[System.Windows.MessageBox]::Show("Saved AI-ready JSON:`n$script:lastExport",'Audit Desk')})
$controls.OpenButton.Add_Click({Start-Process explorer.exe "/select,`"$script:lastExport`""})
$window.ShowDialog()|Out-Null
