rule WindowsShell_s3 {
  meta:
    author = Spider
    comment = None
    date = 2016-03-26
    description = Detects simple Windows shell - file s3.exe
    family = None
    hacker = None
    hash = 344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/odzhan/shells/
    threatname = WindowsShell[s3
    threattype = s3.yar
  strings:
    $s1 = "cmd                  - execute cmd.exe" fullword ascii
    $s2 = "\\\\.\\pipe\\%08X" fullword ascii
    $s3 = "get <remote> <local> - download file" fullword ascii
    $s4 = "[ simple remote shell for windows v3" fullword ascii
    $s5 = "REMOTE: CreateFile(\"%s\")" fullword ascii
    $s6 = "put <local> <remote> - upload file" fullword ascii
    $s7 = "term                 - terminate remote client" fullword ascii
    $s8 = "[ downloading \"%s\" to \"%s\"" fullword ascii
    $s9 = "-l           Listen for incoming connections" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 150KB and 2 of them ) or ( 5 of them )
}