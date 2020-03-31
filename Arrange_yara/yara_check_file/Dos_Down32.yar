rule Dos_Down32 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file Down32.exe
    family = None
    hacker = None
    hash = 0365738acd728021b0ea2967c867f1014fd7dd75
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = Dos[Down32
    threattype = Down32.yar
  strings:
    $s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
    $s6 = "down.exe" fullword wide
    $s15 = "get_Form1" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 137KB and all of them
}