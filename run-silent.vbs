' Script VBScript pour demarrer le serveur en arriere-plan sans fenetre visible
' Usage: Double-cliquez sur ce fichier ou executez-le via le planificateur de taches

Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

' Obtenir le chemin du script
strPath = WScript.ScriptFullName
strFolder = Left(strPath, InStrRev(strPath, "\"))
strScript = strFolder & "run.py"

' Chercher Python dans l'ordre de preference
strPython = ""

' 1. Environnement virtuel pythonw.exe
If fso.FileExists(strFolder & "venv\Scripts\pythonw.exe") Then
    strPython = strFolder & "venv\Scripts\pythonw.exe"
' 2. Environnement virtuel python.exe
ElseIf fso.FileExists(strFolder & "venv\Scripts\python.exe") Then
    strPython = strFolder & "venv\Scripts\python.exe"
Else
    ' 3. Chercher pythonw.exe dans le PATH
    On Error Resume Next
    strPython = WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe")
    If Not fso.FileExists(strPython) Then
        strPython = WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%\Programs\Python\Python311\pythonw.exe")
    End If
    If Not fso.FileExists(strPython) Then
        strPython = WshShell.ExpandEnvironmentStrings("%LOCALAPPDATA%\Programs\Python\Python310\pythonw.exe")
    End If
    If Not fso.FileExists(strPython) Then
        ' Essayer python.exe dans le PATH
        strPython = "python"
    End If
    On Error Goto 0
End If

' Lancer le serveur en arriere-plan (0 = hidden)
If strPython <> "" Then
    WshShell.CurrentDirectory = strFolder
    WshShell.Run """" & strPython & """ """ & strScript & """", 0, False
Else
    MsgBox "Python n'est pas installe ou non trouve.", vbCritical, "Erreur"
End If

Set WshShell = Nothing
Set fso = Nothing
