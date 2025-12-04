; Script generated for x2y AV Ultimate
; SEE THE DOCUMENTATION FOR DETAILS ON CREATING INNO SETUP SCRIPT FILES!

[Setup]
; NOTE: The value of AppId uniquely identifies this application. Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{A32D5678-1234-5678-9ABC-DEF012345678}
AppName=x2y AV Ultimate
AppVersion=7.0
AppPublisher=x2y devs tools
AppPublisherURL=mailto:support@x2ydevs.xyz
AppSupportURL=mailto:support@x2ydevs.xyz
AppUpdatesURL=mailto:support@x2ydevs.xyz
DefaultDirName={autopf}\x2y AV Ultimate
DisableProgramGroupPage=yes
; Remove the following line to run in administrative install mode (install for all users.)
PrivilegesRequired=admin
OutputDir=.\installer_output
OutputBaseFilename=x2y_av_setup
SetupIconFile=assets\x2y_icon.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; NOTE: Don't use "Flags: ignoreversion" on any shared system files
; Main Executable
Source: "build\windows\x64\runner\Release\x2y_av_ultimate.exe"; DestDir: "{app}"; Flags: ignoreversion
; Dependency Files (DLLs, Data, Assets) - CRITICAL FOR FLUTTER APPS
Source: "build\windows\x64\runner\Release\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\x2y AV Ultimate"; Filename: "{app}\x2y_av_ultimate.exe"
Name: "{autodesktop}\x2y AV Ultimate"; Filename: "{app}\x2y_av_ultimate.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\x2y_av_ultimate.exe"; Description: "{cm:LaunchProgram,x2y AV Ultimate}"; Flags: nowait postinstall skipifsilent