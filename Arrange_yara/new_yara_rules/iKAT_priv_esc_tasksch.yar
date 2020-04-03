rule iKAT_priv_esc_tasksch {
  meta:
    author = "Spider"
    comment = "None"
    date = "05.11.14"
    description = "Task Schedulder Local Exploit - Windows local priv-esc using Task Scheduler, published by webDevil. Supports Windows 7 and Vista."
    family = "None"
    hacker = "None"
    hash = "84ab94bff7abf10ffe4446ff280f071f9702cf8b"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "objShell.Run \"schtasks /change /TN wDw00t /disable\",,True" fullword ascii
    $s3 = "objShell.Run \"schtasks /run /TN wDw00t\",,True" fullword ascii
    $s4 = "'objShell.Run \"cmd /c copy C:\\windows\\system32\\tasks\\wDw00t .\",,True" fullword ascii
    $s6 = "a.WriteLine (\"schtasks /delete /f /TN wDw00t\")" fullword ascii
    $s7 = "a.WriteLine (\"net user /add ikat ikat\")" fullword ascii
    $s8 = "a.WriteLine (\"cmd.exe\")" fullword ascii
    $s9 = "strFileName=\"C:\\windows\\system32\\tasks\\wDw00t\"" fullword ascii
    $s10 = "For n = 1 To (Len (hexXML) - 1) step 2" fullword ascii
    $s13 = "output.writeline \" Should work on Vista/Win7/2008 x86/x64\"" fullword ascii
    $s11 = "Set objExecObject = objShell.Exec(\"cmd /c schtasks /query /XML /TN wDw00t\")" fullword ascii
    $s12 = "objShell.Run \"schtasks /create /TN wDw00t /sc monthly /tr \"\"\"+biatchFile+\"" ascii
    $s14 = "a.WriteLine (\"net localgroup administrators /add v4l\")" fullword ascii
    $s20 = "Set ts = fso.createtextfile (\"wDw00t.xml\")" fullword ascii
  condition:
    2 of them
}