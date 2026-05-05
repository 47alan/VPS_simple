' Xshell VBS: download install.sh and open the interactive VPS setup menu.

Option Explicit

' Change this if your repository URL is different.
Const INSTALL_URL = "https://raw.githubusercontent.com/47alan/VPS_simple/main/install.sh"

Sub Main()
    xsh.Screen.Synchronous = True

    Dim cmd
    cmd = "set -e; " & _
          "if [ ""$(id -u)"" -eq 0 ]; then SUDO=''; else SUDO='sudo'; fi; " & _
          "if ! command -v curl >/dev/null 2>&1; then " & _
          "$SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y; " & _
          "$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates; fi; " & _
          "curl -fsSL '" & INSTALL_URL & "' -o /tmp/reverse-proxy-install.sh; " & _
          "chmod +x /tmp/reverse-proxy-install.sh; " & _
          "if [ ""$(id -u)"" -eq 0 ]; then " & _
          "bash /tmp/reverse-proxy-install.sh menu; " & _
          "else sudo bash /tmp/reverse-proxy-install.sh menu; fi"

    xsh.Screen.Send cmd & vbCr
End Sub
