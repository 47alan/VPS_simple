' Xshell VBS: install CLIProxyAPI Docker container on the current SSH session.

Option Explicit

' Change this if your repository URL is different.
Const INSTALL_URL = "https://raw.githubusercontent.com/47alan/VPS_simple/main/install.sh"

Const CLI_PROXY_DIR = "/opt/cli-proxy-api"
Const CLI_PROXY_BIND_IP = "127.0.0.1"
Const CLI_PROXY_API_PORT = "8317"
Const CLI_PROXY_DOMAIN = ""
Const SSL_CERT_PATH = ""
Const SSL_KEY_PATH = ""

Sub Main()
    xsh.Screen.Synchronous = True

    Dim envPart
    envPart = "CLI_PROXY_DIR='" & CLI_PROXY_DIR & "' " & _
              "CLI_PROXY_BIND_IP='" & CLI_PROXY_BIND_IP & "' " & _
              "CLI_PROXY_API_PORT='" & CLI_PROXY_API_PORT & "'"

    If CLI_PROXY_DOMAIN <> "" Then
        envPart = envPart & " CLI_PROXY_DOMAIN='" & CLI_PROXY_DOMAIN & "'"
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
          envPart & " bash /tmp/reverse-proxy-install.sh install-cli-proxy; " & _
          "else sudo " & envPart & " bash /tmp/reverse-proxy-install.sh install-cli-proxy; fi"

    xsh.Screen.Send cmd & vbCr
End Sub
