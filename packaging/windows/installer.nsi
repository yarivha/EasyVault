; ============================================================================
; installer.nsi — Windows installer for EasyVault (built by makensis on CI)
;
; Built on Ubuntu via:
;   makensis -DVERSION=<v> -DINSTALLER_NAME=<name>.exe packaging/windows/installer.nsi
; makensis runs with the script's directory as the working dir, so File/OutFile
; paths are relative to packaging/windows/. The CI copies easyvault.exe,
; config.toml.example and README.md into this directory before building.
; ============================================================================

!define APPNAME "EasyVault"
!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifdef INSTALLER_NAME
  OutFile "${INSTALLER_NAME}"
!else
  OutFile "easyvault-setup.exe"
!endif

!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"

Name "${APPNAME} ${VERSION}"
InstallDir "$PROGRAMFILES64\${APPNAME}"
RequestExecutionLevel admin
Unicode true

Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

; ----------------------------------------------------------------------------
; Install — copy binary + sample config + docs, register uninstaller & shortcut.
; ----------------------------------------------------------------------------
Section "Install"
  SetShellVarContext all
  SetRegView 64
  SetOutPath "$INSTDIR"
  File "easyvault.exe"
  File "config.toml.example"
  File "README.md"

  WriteUninstaller "$INSTDIR\uninstall.exe"
  CreateShortcut "$SMPROGRAMS\${APPNAME}.lnk" "$INSTDIR\easyvault.exe"

  WriteRegStr HKLM "${UNINSTKEY}" "DisplayName"           "${APPNAME}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion"        "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" "Publisher"             "EasyVault"
  WriteRegStr HKLM "${UNINSTKEY}" "UninstallString"       "$\"$INSTDIR\uninstall.exe$\""
  WriteRegStr HKLM "${UNINSTKEY}" "QuietUninstallString"  "$\"$INSTDIR\uninstall.exe$\" /S"
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoRepair" 1
SectionEnd

; ----------------------------------------------------------------------------
; Uninstall — remove files, shortcut and registry keys.
; ----------------------------------------------------------------------------
Section "Uninstall"
  SetShellVarContext all
  SetRegView 64
  Delete "$INSTDIR\easyvault.exe"
  Delete "$INSTDIR\config.toml.example"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$SMPROGRAMS\${APPNAME}.lnk"
  RMDir "$INSTDIR"

  DeleteRegKey HKLM "${UNINSTKEY}"
SectionEnd
