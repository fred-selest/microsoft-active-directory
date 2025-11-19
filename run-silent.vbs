' Script VBScript pour demarrer le serveur en arriere-plan sans fenetre visible
' Usage: Double-cliquez sur ce fichier ou executez-le via le planificateur de taches

Set WshShell = CreateObject("WScript.Shell")

' Obtenir le chemin du script
strPath = WScript.ScriptFullName
strFolder = Left(strPath, InStrRev(strPath, "\"))

' Chemin vers Python dans l'environnement virtuel
strPython = strFolder & "venv\Scripts\pythonw.exe"
strScript = strFolder & "run.py"

' Verifier si pythonw.exe existe
Set fso = CreateObject("Scripting.FileSystemObject")
If Not fso.FileExists(strPython) Then
    ' Essayer avec python.exe standard
    strPython = strFolder & "venv\Scripts\python.exe"
End If

' Lancer le serveur en arriere-plan (0 = hidden)
WshShell.Run """" & strPython & """ """ & strScript & """", 0, False

Set WshShell = Nothing
Set fso = Nothing
