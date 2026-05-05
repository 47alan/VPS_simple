' Xshell VBS: install SkrBTSo Helper Docker container on the current SSH session.

Option Explicit

' Change this if your repository URL is different.
Const INSTALL_URL = "https://raw.githubusercontent.com/47alan/VPS_simple/main/install.sh"

Const SKRBTSO_DIR = "/opt/skrbtso-helper"
Const SKRBTSO_DOMAIN = ""
Const SSL_CERT_PATH = ""
Const SSL_KEY_PATH = ""

Sub Main()
    xsh.Screen.Synchronous = True

    Dim envPart
    envPart = "SKRBTSO_DIR='" & SKRBTSO_DIR & "'"

    If SKRBTSO_DOMAIN <> "" Then
        envPart = envPart & " SKRBTSO_DOMAIN='" & SKRBTSO_DOMAIN & "'"
    End If

    If SSL_CERT_PATH <> "" Then
        envPart = envPart & " SSL_CERT_PATH='" & SSL_CERT_PATH & "'"
    End If

    If SSL_KEY_PATH <> "" Then
        envPart = envPart & " SSL_KEY_PATH='" & SSL_KEY_PATH & "'"
    End If

    Dim cmd
    cmd = "set -e; " & _
          "if [ ""$(id -u)"" -eq 0 ]; then SUDO=''; else SUDO='sudo'; fi; " & _
          "if ! command -v curl >/dev/null 2>&1; then " & _
          "$SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y; " & _
          "$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates; fi; " & _
          "curl -fsSL '" & INSTALL_URL & "' -o /tmp/reverse-proxy-install.sh; " & _
          "chmod +x /tmp/reverse-proxy-install.sh; " & _
          "if [ ""$(id -u)"" -eq 0 ]; then " & _
          envPart & " bash /tmp/reverse-proxy-install.sh install-skrbtso; " & _
          "else sudo " & envPart & " bash /tmp/reverse-proxy-install.sh install-skrbtso; fi"

    xsh.Screen.Send cmd & vbCr
End Sub
