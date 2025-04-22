[Setup]
AppName=ZenithScan
AppVersion=1.0
DefaultDirName={pf}\ZenithScan
DefaultGroupName=ZenithScan
UninstallDisplayIcon={app}\ZenithScan.exe
OutputDir=dist
OutputBaseFilename=ZenithScan-Setup
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64

[Files]
Source: "dist\ZenithScan\ZenithScan.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "DejaVuSans.ttf"; DestDir: "{app}"; Flags: ignoreversion
Source: "DejaVuSans-Bold.ttf"; DestDir: "{app}"; Flags: ignoreversion
Source: "ZenithScan.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\ZenithScan"; Filename: "{app}\ZenithScan.exe"
Name: "{commondesktop}\ZenithScan"; Filename: "{app}\ZenithScan.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Criar atalho na área de trabalho"; GroupDescription: "Opções adicionais:"

[Run]
Filename: "{app}\ZenithScan.exe"; Description: "Executar ZenithScan agora"; Flags: nowait postinstall skipifsilent
