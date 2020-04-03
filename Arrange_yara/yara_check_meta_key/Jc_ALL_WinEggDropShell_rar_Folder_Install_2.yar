rule Jc_ALL_WinEggDropShell_rar_Folder_Install_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file Install.exe"
    family = "None"
    hacker = "None"
    hash = "95866e917f699ee74d4735300568640ea1a05afd"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "http://go.163.com/sdemo" fullword wide
    $s2 = "Player.tmp" fullword ascii
    $s3 = "Player.EXE" fullword wide
    $s4 = "mailto:sdemo@263.net" fullword ascii
    $s5 = "S-Player.exe" fullword ascii
    $s9 = "http://www.BaiXue.net (" fullword wide
  condition:
    all of them
}