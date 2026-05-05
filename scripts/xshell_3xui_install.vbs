' Xshell VBS: install 3x-ui Docker container on the current SSH session.

Option Explicit

' Change this if your repository URL is different.
Const INSTALL_URL = "https://raw.githubusercontent.com/47alan/VPS_simple/main/install.sh"

Const XUI_DIR = "/opt/3x-ui"
Const XUI_CONTAINER_NAME = "3xui_app"
Const OPEN_LOCAL_FIREWALL = "1"

Sub Main()
    xsh.Screen.Synchronous = True

    Dim envPart
    envPart = "XUI_DIR='" & XUI_DIR & "' " & _
              "XUI_CONTAINER_NAME='" & XUI_CONTAINER_NAME & "' " & _
              "OPEN_LOCAL_FIREWALL='" & OPEN_LOCAL_FIREWALL & "'"

    Dim cmd
    cmd = "set -e; " & _
          "if [ ""$(id -u)"" -eq 0 ]; then SUDO=''; else SUDO='sudo'; fi; " & _
          "if ! command -v curl >/dev/null 2>&1; then " & _
          "$SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y; " & _
          "$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates; fi; " & _
          "curl -fsSL '" & INSTALL_URL & "' -o /tmp/reverse-proxy-install.sh; " & _
          "chmod +x /tmp/reverse-proxy-install.sh; " & _
          "if [ ""$(id -u)"" -eq 0 ]; then " & _
          envPart & " bash /tmp/reverse-proxy-install.sh install-3x-ui; " & _
          "else sudo " & envPart & " bash /tmp/reverse-proxy-install.sh install-3x-ui; fi"

    xsh.Screen.Send cmd & vbCr
End Sub
