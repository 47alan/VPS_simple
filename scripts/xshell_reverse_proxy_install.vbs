' Xshell VBS: one-click install Docker Nginx reverse proxy on the current SSH session.
' Usage:
' 1. Upload/publish this repository so INSTALL_URL points to the raw install.sh URL.
' 2. Connect to an Ubuntu 24.04 server in Xshell.
' 3. Run this VBS from Xshell Script Manager.

Option Explicit

' Change this if your repository URL is different.
Const INSTALL_URL = "https://raw.githubusercontent.com/47alan/VPS_simple/main/install.sh"

' Basic install options.
Const PROJECT_DIR = "/opt/reverse-proxy"
Const CONTAINER_NAME = "reverse-proxy"
Const NETWORK_NAME = "proxy-net"
Const CREATE_SITE = "0"
Const SYSTEM_UPGRADE = "1"
Const INSTALL_3XUI = "0"
Const INSTALL_CLIPROXY = "0"
Const INSTALL_SKRBTSO = "0"
Const XUI_DIR = "/opt/3x-ui"
Const XUI_CONTAINER_NAME = "3xui_app"
Const XUI_DOMAIN = ""
Const CLI_PROXY_DIR = "/opt/cli-proxy-api"
Const CLI_PROXY_BIND_IP = "127.0.0.1"
Const CLI_PROXY_DOMAIN = ""
Const SKRBTSO_DOMAIN = ""
Const SSL_CERT_PATH = ""
Const SSL_KEY_PATH = ""

' Optional first site. Leave empty to initialize reverse proxy only.
Const DOMAIN = ""
Const UPSTREAM = ""

Sub Main()
    xsh.Screen.Synchronous = True

    Dim envPart
    envPart = "PROJECT_DIR='" & PROJECT_DIR & "' " & _
              "CONTAINER_NAME='" & CONTAINER_NAME & "' " & _
              "NETWORK_NAME='" & NETWORK_NAME & "' " & _
              "CREATE_SITE='" & CREATE_SITE & "' " & _
              "SYSTEM_UPGRADE='" & SYSTEM_UPGRADE & "' " & _
              "INSTALL_3XUI='" & INSTALL_3XUI & "' " & _
              "INSTALL_CLIPROXY='" & INSTALL_CLIPROXY & "' " & _
              "INSTALL_SKRBTSO='" & INSTALL_SKRBTSO & "' " & _
              "XUI_DIR='" & XUI_DIR & "' " & _
              "XUI_CONTAINER_NAME='" & XUI_CONTAINER_NAME & "' " & _
              "CLI_PROXY_DIR='" & CLI_PROXY_DIR & "' " & _
              "CLI_PROXY_BIND_IP='" & CLI_PROXY_BIND_IP & "'"

    If DOMAIN <> "" Then
        envPart = envPart & " DOMAIN='" & DOMAIN & "'"
    End If

    If UPSTREAM <> "" Then
        envPart = envPart & " UPSTREAM='" & UPSTREAM & "'"
    End If

    If XUI_DOMAIN <> "" Then
        envPart = envPart & " XUI_DOMAIN='" & XUI_DOMAIN & "'"
    End If

    If CLI_PROXY_DOMAIN <> "" Then
        envPart = envPart & " CLI_PROXY_DOMAIN='" & CLI_PROXY_DOMAIN & "'"
    End If

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
          envPart & " bash /tmp/reverse-proxy-install.sh install; " & _
          "else sudo " & envPart & " bash /tmp/reverse-proxy-install.sh install; fi"

    xsh.Screen.Send cmd & vbCr
End Sub
