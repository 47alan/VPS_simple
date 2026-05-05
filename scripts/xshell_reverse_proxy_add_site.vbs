' Xshell VBS: add one HTTPS reverse proxy site on the current SSH session.
' Before running, put certificates on the server:
' /opt/reverse-proxy/ssl/<domain>/fullchain.pem
' /opt/reverse-proxy/ssl/<domain>/privkey.pem

Option Explicit

' Change this if your repository URL is different.
Const INSTALL_URL = "https://raw.githubusercontent.com/47alan/VPS_simple/main/install.sh"

' Must be changed before use.
Const DOMAIN = "example.com"
Const UPSTREAM = "app-container:8080"

Const PROJECT_DIR = "/opt/reverse-proxy"
Const CONTAINER_NAME = "reverse-proxy"
Const NETWORK_NAME = "proxy-net"

Sub Main()
    xsh.Screen.Synchronous = True

    Dim envPart
    envPart = "PROJECT_DIR='" & PROJECT_DIR & "' " & _
              "CONTAINER_NAME='" & CONTAINER_NAME & "' " & _
              "NETWORK_NAME='" & NETWORK_NAME & "' " & _
              "DOMAIN='" & DOMAIN & "' " & _
              "UPSTREAM='" & UPSTREAM & "'"

    Dim cmd
    cmd = "set -e; " & _
          "if [ ""$(id -u)"" -eq 0 ]; then SUDO=''; else SUDO='sudo'; fi; " & _
          "if ! command -v curl >/dev/null 2>&1; then " & _
          "$SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y; " & _
          "$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates; fi; " & _
          "curl -fsSL '" & INSTALL_URL & "' -o /tmp/reverse-proxy-install.sh; " & _
          "chmod +x /tmp/reverse-proxy-install.sh; " & _
          "if [ ""$(id -u)"" -eq 0 ]; then " & _
          envPart & " bash /tmp/reverse-proxy-install.sh add-site; " & _
          "else sudo " & envPart & " bash /tmp/reverse-proxy-install.sh add-site; fi"

    xsh.Screen.Send cmd & vbCr
End Sub
