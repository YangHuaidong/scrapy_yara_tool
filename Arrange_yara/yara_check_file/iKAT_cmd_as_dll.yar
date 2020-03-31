rule iKAT_cmd_as_dll {
  meta:
    author = Spider
    comment = None
    date = 05.11.14
    description = iKAT toolset file cmd.dll ReactOS file cloaked
    family = dll
    hacker = None
    hash = b5d0ba941efbc3b5c97fe70f70c14b2050b8336a
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://ikat.ha.cked.net/Windows/functions/ikatfiles.html
    score = 65
    threatname = iKAT[cmd]/as.dll
    threattype = cmd
  strings:
    $s1 = "cmd.exe" fullword wide
    $s2 = "ReactOS Development Team" fullword wide
    $s3 = "ReactOS Command Processor" fullword wide
    $ext = "extension: .dll" nocase
  condition:
    all of ($s*) and $ext
}