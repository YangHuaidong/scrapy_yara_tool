rule ShellCrew_StreamEx_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "Auto-generated rule - file 81f411415aefa5ad7f7ed2365d9a18d0faf33738617afc19215b69c23f212c07"
    family = "None"
    hacker = "None"
    hash1 = "81f411415aefa5ad7f7ed2365d9a18d0faf33738617afc19215b69c23f212c07"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "cmd.exe /c  \"%s\"" fullword wide
    $s3 = "uac\\bin\\install_test.pdb" fullword ascii
    $s5 = "uncompress error:%d %s" fullword ascii
    $s7 = "%s\\AdobeBak\\Proc.dat" fullword wide
    $s8 = "e:\\workspace\\boar" fullword ascii
    $s12 = "$\\data.ini" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 1000KB and 4 of them )
}