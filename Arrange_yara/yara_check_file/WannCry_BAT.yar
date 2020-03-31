rule WannCry_BAT {
  meta:
    author = Spider
    comment = None
    date = 2017-05-12
    description = Detects WannaCry Ransomware BATCH File
    family = None
    hacker = None
    hash1 = f01b7f52e3cb64f01ddc248eb6ae871775ef7cb4297eba5d230d0345af9a5077
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://goo.gl/HG2j5T
    threatname = WannCry[BAT
    threattype = BAT.yar
  strings:
    $s1 = "@.exe\">> m.vbs" ascii
    $s2 = "cscript.exe //nologo m.vbs" fullword ascii
    $s3 = "echo SET ow = WScript.CreateObject(\"WScript.Shell\")> " ascii
    $s4 = "echo om.Save>> m.vbs" fullword ascii
  condition:
    ( uint16(0) == 0x6540 and filesize < 1KB and 1 of them )
}