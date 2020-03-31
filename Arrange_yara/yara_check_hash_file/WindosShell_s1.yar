rule WindosShell_s1 {
  meta:
    author = Spider
    comment = None
    date = 2016-03-26
    description = Detects simple Windows shell - file s1.exe
    family = None
    hacker = None
    hash = 4a397497cfaf91e05a9b9d6fa6e335243cca3f175d5d81296b96c13c624818bd
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/odzhan/shells/
    threatname = WindosShell[s1
    threattype = s1.yar
  strings:
    $s1 = "[ executing cmd.exe" fullword ascii
    $s2 = "[ simple remote shell for windows v1" fullword ascii
    $s3 = "-p <number>  Port number to use (default is 443)" fullword ascii
    $s4 = "usage: s1 <address> [options]" fullword ascii
    $s5 = "[ waiting for connections on %s" fullword ascii
    $s6 = "-l           Listen for incoming connections" fullword ascii
    $s7 = "[ connection from %s" fullword ascii
    $s8 = "[ %c%c requires parameter" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 150KB and 2 of them ) or ( 5 of them )
}