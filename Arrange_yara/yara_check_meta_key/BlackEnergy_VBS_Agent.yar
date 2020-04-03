rule BlackEnergy_VBS_Agent {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-01-03"
    description = "Detects VBS Agent from BlackEnergy Report - file Dropbearrun.vbs"
    family = "None"
    hacker = "None"
    hash = "b90f268b5e7f70af1687d9825c09df15908ad3a6978b328dc88f96143a64af0f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "WshShell.Run \"dropbear.exe -r rsa -d dss -a -p 6789\", 0, false" fullword ascii
    $s1 = "WshShell.CurrentDirectory = \"C:\\WINDOWS\\TEMP\\Dropbear\\\"" fullword ascii
    $s2 = "Set WshShell = CreateObject(\"WScript.Shell\")" fullword ascii /* Goodware String - occured 1 times */
  condition:
    filesize < 1KB and 2 of them
}