rule WindowsShell_s4 {
  meta:
    author = Spider
    comment = None
    date = 2016-03-26
    description = Detects simple Windows shell - file s4.exe
    family = None
    hacker = None
    hash = f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/odzhan/shells/
    threatname = WindowsShell[s4
    threattype = s4.yar
  strings:
    $s1 = "cmd                  - execute cmd.exe" fullword ascii
    $s2 = "\\\\.\\pipe\\%08X" fullword ascii
    $s3 = "get <remote> <local> - download file" fullword ascii
    $s4 = "[ simple remote shell for windows v4" fullword ascii
    $s5 = "REMOTE: CreateFile(\"%s\")" fullword ascii
    $s6 = "[ downloading \"%s\" to \"%s\"" fullword ascii
    $s7 = "[ uploading \"%s\" to \"%s\"" fullword ascii
    $s8 = "-l           Listen for incoming connections" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 175KB and 2 of them ) or ( 5 of them )
}