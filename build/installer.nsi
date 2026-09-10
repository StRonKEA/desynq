Unicode true
RequestExecutionLevel admin

# Switch to repository root directory
!cd ".."

!include "MUI2.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"

# Application metadata
!define PRODUCT_NAME "Desynq"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_PUBLISHER "Desynq Team"
!define PRODUCT_WEB_SITE "https://github.com/StRonKEA/desynq"
!define PRODUCT_EXE "desynq.exe"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"

# Visual styling & Icons
!define MUI_ICON "ui\icon.ico"
!define MUI_UNICON "ui\icon.ico"
!define MUI_ABORTWARNING

# Installer Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_RUN "$INSTDIR\${PRODUCT_EXE}"
!insertmacro MUI_PAGE_FINISH

# Uninstaller Pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

# Languages
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Turkish"

Name "${PRODUCT_NAME}"
OutFile "Desynq-Setup.exe"
InstallDir "$PROGRAMFILES64\${PRODUCT_NAME}"
ShowInstDetails show
ShowUnInstDetails show

Function .onInit
    ${IfNot} ${RunningX64}
        MessageBox MB_ICONSTOP|MB_OK "Desynq requires a 64-bit Windows operating system."
        Abort
    ${EndIf}
FunctionEnd

Section "MainSection" SEC01
    SetOutPath "$INSTDIR"
    SetOverwrite on

    # Terminate old instances if running
    nsExec::Exec 'taskkill /F /IM desynq.exe /IM winws2.exe'

    # Main Executable
    File "desynq.exe"
    File "README.md"

    # Embedded Zapret & WinDivert Driver Tools
    SetOutPath "$INSTDIR\tools\zapret-winws"
    File /r "tools\zapret-winws\*.*"

    # Create Uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    # Create Shortcuts
    CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
    CreateShortcut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" "$INSTDIR\${PRODUCT_EXE}" "" "$INSTDIR\${PRODUCT_EXE}" 0
    CreateShortcut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk" "$INSTDIR\Uninstall.exe" "" "$INSTDIR\Uninstall.exe" 0
    CreateShortcut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\${PRODUCT_EXE}" "" "$INSTDIR\${PRODUCT_EXE}" 0

    # Add/Remove Programs Registry Keys
    WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "${PRODUCT_NAME}"
    WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" "$INSTDIR\Uninstall.exe"
    WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\${PRODUCT_EXE}"
    WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
    WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
    WriteRegStr HKLM "${UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
    WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
    WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
    # Stop and remove background services
    nsExec::Exec 'sc.exe stop desynq-dns'
    nsExec::Exec 'sc.exe delete desynq-dns'
    nsExec::Exec 'sc.exe stop desynq-dpi'
    nsExec::Exec 'sc.exe delete desynq-dpi'
    nsExec::Exec 'sc.exe stop dpi-bypass'
    nsExec::Exec 'sc.exe delete dpi-bypass'

    # Terminate running processes
    nsExec::Exec 'taskkill /F /IM desynq.exe /IM winws2.exe'

    # Unpin managed hosts using built-in command
    nsExec::Exec '"$INSTDIR\${PRODUCT_EXE}" remove -dns'

    # Remove Shortcuts
    Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
    Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk"
    Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
    RMDir "$SMPROGRAMS\${PRODUCT_NAME}"

    # Remove Installed Files
    Delete "$INSTDIR\${PRODUCT_EXE}"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir /r "$INSTDIR\tools"
    RMDir /r "$INSTDIR\config"
    RMDir /r "$INSTDIR\logs"
    RMDir "$INSTDIR"

    # Clean Registry
    DeleteRegKey HKLM "${UNINST_KEY}"
SectionEnd
