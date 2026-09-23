; Inno Setup script for YEMU. Built by scripts/build.py --installer (or the release workflow):
;   iscc /DAppVersion=0.5.0 /DSourceDir=..\..\dist\YEMU /DOutputDir=..\..\dist packaging\windows\yemu.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist\YEMU"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist"
#endif

[Setup]
AppId={{7B0F3C52-9E2B-4B7A-9D55-3E4D2A1F9C11}
AppName=YEMU
AppVersion={#AppVersion}
AppPublisher=Armaan Guha
AppPublisherURL=https://github.com/ogshrug/YEMU
AppSupportURL=https://github.com/ogshrug/YEMU/issues
DefaultDirName={autopf}\YEMU
DefaultGroupName=YEMU
DisableProgramGroupPage=yes
OutputDir={#OutputDir}
OutputBaseFilename=YEMU-{#AppVersion}-windows-x64-setup
SetupIconFile=..\..\yemu\gui\assets\yemu.ico
UninstallDisplayIcon={app}\yemu-gui.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; per-user install by default (no admin needed); admins can choose all users
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ChangesEnvironment=yes

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "addtopath"; Description: "Add the yemu command-line tool to PATH"; GroupDescription: "Command line:"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\YEMU"; Filename: "{app}\yemu-gui.exe"
Name: "{group}\Uninstall YEMU"; Filename: "{uninstallexe}"
Name: "{autodesktop}\YEMU"; Filename: "{app}\yemu-gui.exe"; Tasks: desktopicon

[Registry]
Root: HKA; Subkey: "{code:EnvKey}"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
  Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\yemu-gui.exe"; Description: "Launch YEMU"; Flags: nowait postinstall skipifsilent

[Code]
function EnvKey(Param: String): String;
begin
  if IsAdminInstallMode then
    Result := 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  else
    Result := 'Environment';
end;

function NeedsAddPath(Dir: String): Boolean;
var
  Paths: String;
  RootKey: Integer;
begin
  if IsAdminInstallMode then RootKey := HKEY_LOCAL_MACHINE else RootKey := HKEY_CURRENT_USER;
  if not RegQueryStringValue(RootKey, EnvKey(''), 'Path', Paths) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') = 0;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Paths, Dir: String;
  RootKey, P: Integer;
begin
  if CurUninstallStep <> usPostUninstall then exit;
  if IsAdminInstallMode then RootKey := HKEY_LOCAL_MACHINE else RootKey := HKEY_CURRENT_USER;
  Dir := ExpandConstant('{app}');
  if RegQueryStringValue(RootKey, EnvKey(''), 'Path', Paths) then
  begin
    P := Pos(';' + Uppercase(Dir), Uppercase(Paths));
    if P > 0 then
    begin
      Delete(Paths, P, Length(Dir) + 1);
      RegWriteExpandStringValue(RootKey, EnvKey(''), 'Path', Paths);
    end;
  end;
end;
