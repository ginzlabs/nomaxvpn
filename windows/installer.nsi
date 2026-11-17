; The NoMax installer. cmd/ops windows builds it with makensis:
;   makensis -DVERSION=1.0 -DBUILD=120 -DSRC=dist/windows -DOUT=dist/nomax-setup.exe windows/installer.nsi
; SRC has NoMax.exe, wintun.dll, wintun-LICENSE.txt and NoMax.ico.

Unicode true
ManifestDPIAware true
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "x64.nsh"
!include "LogicLib.nsh"

Name "NoMax"
OutFile "${OUT}"
InstallDir "$PROGRAMFILES64\NoMax"
RequestExecutionLevel admin
BrandingText "NoMax ${VERSION} (${BUILD})"
VIProductVersion "1.0.0.${BUILD}"
VIAddVersionKey "ProductName" "NoMax"
VIAddVersionKey "FileDescription" "NoMax installer"
VIAddVersionKey "ProductVersion" "${VERSION} (${BUILD})"
VIAddVersionKey "FileVersion" "1.0.0.${BUILD}"
VIAddVersionKey "LegalCopyright" "GPLv3"

!define MUI_ICON "${SRC}\NoMax.ico"
!define MUI_UNICON "${SRC}\NoMax.ico"
!define MUI_FINISHPAGE_RUN "$INSTDIR\NoMax.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Open NoMax"
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

!define UNINSTALL "Software\Microsoft\Windows\CurrentVersion\Uninstall\NoMax"

; An open NoMax holds its files. It's asked to disconnect and close (wmQuitNoMax
; in windows/sys.go), and ended if it's still there after five seconds.
!macro CloseNoMax
  FindWindow $0 "webview" "NoMax"
  ${If} $0 <> 0
    SendMessage $0 0x804E 0 0 /TIMEOUT=5000
  ${EndIf}
  StrCpy $1 0
  ${Do}
    nsExec::Exec 'cmd /c tasklist /FI "IMAGENAME eq NoMax.exe" /NH | find /I "NoMax.exe"'
    Pop $2
    ${If} $2 <> 0
    ${OrIf} $1 >= 10
      ${Break}
    ${EndIf}
    Sleep 500
    IntOp $1 $1 + 1
  ${Loop}
  nsExec::Exec 'taskkill /IM NoMax.exe /F'
  Sleep 300
!macroend

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "NoMax needs 64-bit Windows."
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

; Installing over an older NoMax updates it; the device stays joined, as its
; keys and settings live in %LOCALAPPDATA%\NoMax.
Section
  !insertmacro CloseNoMax
  SetOutPath "$INSTDIR"
  File "${SRC}\NoMax.exe"
  File "${SRC}\wintun.dll"
  File "${SRC}\wintun-LICENSE.txt"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateShortcut "$SMPROGRAMS\NoMax.lnk" "$INSTDIR\NoMax.exe"
  CreateShortcut "$DESKTOP\NoMax.lnk" "$INSTDIR\NoMax.exe"
  WriteRegStr HKLM "${UNINSTALL}" "DisplayName" "NoMax"
  WriteRegStr HKLM "${UNINSTALL}" "DisplayVersion" "${VERSION} (${BUILD})"
  WriteRegStr HKLM "${UNINSTALL}" "Publisher" "NoMax"
  WriteRegStr HKLM "${UNINSTALL}" "DisplayIcon" "$INSTDIR\NoMax.exe"
  WriteRegStr HKLM "${UNINSTALL}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${UNINSTALL}" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKLM "${UNINSTALL}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  !insertmacro CloseNoMax
  Delete "$INSTDIR\NoMax.exe"
  Delete "$INSTDIR\wintun.dll"
  Delete "$INSTDIR\wintun-LICENSE.txt"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\NoMax.lnk"
  Delete "$DESKTOP\NoMax.lnk"
  DeleteRegKey HKLM "${UNINSTALL}"
SectionEnd
