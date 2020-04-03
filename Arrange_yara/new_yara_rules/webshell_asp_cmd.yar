rule webshell_asp_cmd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cmd.asp"
    family = "None"
    hacker = "None"
    hash = "895ca846858c315a3ff8daa7c55b3119"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
    $s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
    $s3 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
  condition:
    1 of them
}