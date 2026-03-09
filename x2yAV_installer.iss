; ╔══════════════════════════════════════════════════════════════════════════╗
; ║   x2y AV Ultimate v8.0.5  —  Final Production Installer Script           ║
; ║   Fixes: BEGIN expected, GetSpaceOnDisk64 params, and Launch Failure     ║
; ╚══════════════════════════════════════════════════════════════════════════╝

#define AppName        "x2y AV Ultimate"
#define AppVersion     "8.0.5"
#define AppPublisher   "x2y Devs Tools"
#define AppURL         "https://x2ydevs.xyz"
#define AppExeName     "x2yAV.exe"
#define AppDescription "x2y AV Ultimate - Real-time Antivirus Protection"
#define AppCopyright   "Copyright (C) 2025 x2y Devs Tools"
#define BuildDir       "dist\x2yAV"

[Setup]
AppId={{A7F3C2D1-4E8B-4F9A-B2C3-D4E5F6A7B8C9}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppCopyright={#AppCopyright}
DefaultDirName={autopf}\x2yAVUltimate
DefaultGroupName={#AppName}
PrivilegesRequired=admin
OutputDir=installer_output
OutputBaseFilename=x2yAV_Setup_v{#AppVersion}
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\{#AppExeName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
english.AppRunningMsg=x2y AV Ultimate is currently running. The installer will close it before continuing. Proceed?
english.KeepDataMsg=Do you want to keep your scan history and settings?
english.LowDiskMsg=The selected drive has less than 200 MB free. Continue anyway?
english.TaskStartup=Run x2y AV automatically at Windows startup

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "startup"; Description: "{cm:TaskStartup}"; GroupDescription: "Real-Time Protection"

[Files]
; Core Files from PyInstaller
Source: "{#BuildDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{userdesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Registry]
; Windows startup entry
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "x2yAVUltimate"; ValueData: """{app}\{#AppExeName}"""; Flags: uninsdeletevalue; Tasks: startup

[Run]
; FIX: WorkingDir ensures the app finds its local files/signatures
Filename: "{app}\{#AppExeName}"; \
    Description: "Launch {#AppName}"; \
    WorkingDir: "{app}"; \
    Flags: nowait postinstall skipifsilent runascurrentuser

[Code]

// Check if app is currently running to prevent file-in-use errors
function IsAppRunning: Boolean;
var
  RC: Integer;
begin
  Result := False;
  if Exec('cmd.exe', '/c tasklist /FI "IMAGENAME eq {#AppExeName}" | findstr /I "{#AppExeName}"',
          '', SW_HIDE, ewWaitUntilTerminated, RC) then
  begin
    Result := (RC = 0);
  end;
end;

function InitializeSetup: Boolean;
var
  RC: Integer;
begin
  Result := True;
  if IsAppRunning then
  begin
    if MsgBox(ExpandConstant('{cm:AppRunningMsg}'), mbConfirmation, MB_YESNO) = IDNO then
    begin
      Result := False;
      Exit;
    end;
    // Force kill before install
    Exec('taskkill.exe', '/F /IM {#AppExeName}', '', SW_HIDE, ewWaitUntilTerminated, RC);
    Sleep(1000);
  end;
end;

// Modern 64-bit disk space check
function NextButtonClick(CurPageID: Integer): Boolean;
var
  FreeSpace, TotalSpace: Int64; 
begin
  Result := True;
  if CurPageID = wpSelectDir then
  begin
    // Fixed with 3 parameters as required by Inno Setup 6+
    if GetSpaceOnDisk64(ExtractFileDrive(WizardDirValue), FreeSpace, TotalSpace) then
    begin
      if FreeSpace < 209715200 then
      begin
        if MsgBox(ExpandConstant('{cm:LowDiskMsg}'), mbConfirmation, MB_YESNO) = IDNO then
          Result := False;
      end;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  SettingsDir, SettingsFile, JsonContent: String;
begin
  if CurStep = ssPostInstall then
  begin
    SettingsDir  := ExpandConstant('{userappdata}') + '\.x2y_av';
    SettingsFile := SettingsDir + '\settings.json';
    if not DirExists(SettingsDir) then ForceDirectories(SettingsDir);

    if not FileExists(SettingsFile) then
    begin
      // Initialize privacy-centric settings
      JsonContent := '{' + #13#10 + 
                     '  "background_shield": true,' + #13#10 + 
                     '  "last_build": "{#AppVersion}"' + #13#10 + 
                     '}';
      SaveStringToFile(SettingsFile, JsonContent, False);
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    // Option to wipe user data on removal
    if MsgBox(ExpandConstant('{cm:KeepDataMsg}'), mbConfirmation, MB_YESNO) = IDNO then
    begin
      DataDir := ExpandConstant('{userappdata}') + '\.x2y_av';
      if DirExists(DataDir) then DelTree(DataDir, True, True, True);
    end;
  end;
end;