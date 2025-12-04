; ============================================
; x2y AV Ultimate - Professional Installer
; Version: 7.0.0
; ============================================

[Setup]
; App Identification
AppId={{A32D5678-1234-5678-9ABC-DEF012345678}
AppName=x2y AV Ultimate
AppVersion=7.0.0
AppVerName=x2y AV Ultimate v7.0.0
AppPublisher=x2y devs tools
AppPublisherURL=https://x2ydevs.xyz
AppSupportURL=mailto:support@x2ydevs.xyz
AppUpdatesURL=mailto:support@x2ydevs.xyz
AppCopyright=Copyright © 2024 x2y devs tools. All rights reserved.

; Installation Settings
DefaultDirName={autopf}\x2y AV Ultimate
DefaultGroupName=x2y AV Ultimate
DisableProgramGroupPage=yes
DisableDirPage=no
AllowNoIcons=yes

; Security & Permissions (CRITICAL FOR ANTIVIRUS)
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
MinVersion=10.0

; Output Settings
OutputDir=.\installer_output
OutputBaseFilename=x2y_av_ultimate_setup_v7.0.0
SetupIconFile=assets\x2y_icon.ico
Compression=lzma
SolidCompression=yes
LZMAUseSeparateProcess=yes

; Installer Appearance
WizardStyle=modern
SetupLogging=yes

; Architecture
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startupicon"; Description: "Run on Windows startup"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Main Application
Source: "build\windows\x64\runner\Release\x2y_av_ultimate.exe"; DestDir: "{app}"; Flags: ignoreversion

; All Dependencies (Flutter Windows Build)
Source: "build\windows\x64\runner\Release\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Start Menu
Name: "{group}\x2y AV Ultimate"; Filename: "{app}\x2y_av_ultimate.exe"
Name: "{group}\{cm:UninstallProgram,x2y AV Ultimate}"; Filename: "{uninstallexe}"

; Desktop
Name: "{autodesktop}\x2y AV Ultimate"; Filename: "{app}\x2y_av_ultimate.exe"; Tasks: desktopicon

; Startup
Name: "{userstartup}\x2y AV Ultimate"; Filename: "{app}\x2y_av_ultimate.exe"; Tasks: startupicon

[Run]
; Launch after installation
Filename: "{app}\x2y_av_ultimate.exe"; Description: "{cm:LaunchProgram,x2y AV Ultimate}"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallDelete]
; Clean up user data
Type: filesandordirs; Name: "{localappdata}\x2y_av_ultimate"
Type: files; Name: "{userstartup}\x2y AV Ultimate.lnk"