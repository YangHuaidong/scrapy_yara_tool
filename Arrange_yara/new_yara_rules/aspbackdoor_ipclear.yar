rule aspbackdoor_ipclear {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file ipclear.vbs"
    family = "None"
    hacker = "None"
    hash = "9f8fdfde4b729516330eaeb9141fb2a7ff7d0098"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Set ServiceObj = GetObject(\"WinNT://\" & objNet.ComputerName & \"/w3svc\")" fullword ascii
    $s1 = "wscript.Echo \"USAGE:KillLog.vbs LogFileName YourIP.\"" fullword ascii
    $s2 = "Set txtStreamOut = fso.OpenTextFile(destfile, ForWriting, True)" fullword ascii
    $s3 = "Set objNet = WScript.CreateObject( \"WScript.Network\" )" fullword ascii
    $s4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
  condition:
    all of them
}