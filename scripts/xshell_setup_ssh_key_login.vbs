' Xshell VBS: configure SSH public-key login safely on the current SSH session.
' Fill SSH_PUBLIC_KEY before running, or leave it empty and paste the key when prompted.

Option Explicit

' Change this if your repository URL is different.
Const SSH_INSTALL_URL = "https://raw.githubusercontent.com/47alan/VPS_simple/main/setup-ssh-key-login.sh"

Const SSH_USER = "root"
Const SSH_PUBLIC_KEY = ""

' Leave SSH_PORT empty to keep the current port. Example: "22222"
Const SSH_PORT = ""

' Keep old SSH port by default to avoid locking yourself out.
Const KEEP_OLD_SSH_PORT = "1"

' Set to "1" only after you confirm private-key login works.
Const DISABLE_PASSWORD_LOGIN = "0"

Sub Main()
    xsh.Screen.Synchronous = True

    Dim envPart
    envPart = "SSH_USER='" & SSH_USER & "' " & _
              "KEEP_OLD_SSH_PORT='" & KEEP_OLD_SSH_PORT & "' " & _
              "DISABLE_PASSWORD_LOGIN='" & DISABLE_PASSWORD_LOGIN & "'"

    If SSH_PUBLIC_KEY <> "" Then
        envPart = envPart & " SSH_PUBLIC_KEY='" & SSH_PUBLIC_KEY & "'"
    End If

    If SSH_PORT <> "" Then
        envPart = envPart & " SSH_PORT='" & SSH_PORT & "'"
    End If

    Dim cmd
    cmd = "set -e; " & _
          "if [ ""$(id -u)"" -eq 0 ]; then SUDO=''; else SUDO='sudo'; fi; " & _
          "if ! command -v curl >/dev/null 2>&1; then " & _
          "$SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y; " & _
          "$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates; fi; " & _
          "curl -fsSL '" & SSH_INSTALL_URL & "' -o /tmp/setup-ssh-key-login.sh; " & _
          "chmod +x /tmp/setup-ssh-key-login.sh; " & _
          "if [ ""$(id -u)"" -eq 0 ]; then " & _
          envPart & " bash /tmp/setup-ssh-key-login.sh; " & _
          "else sudo " & envPart & " bash /tmp/setup-ssh-key-login.sh; fi"

    xsh.Screen.Send cmd & vbCr
End Sub
