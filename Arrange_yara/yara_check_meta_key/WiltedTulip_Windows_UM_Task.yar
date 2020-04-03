rule WiltedTulip_Windows_UM_Task {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-23"
    description = "Detects a Windows scheduled task as used in Operation Wilted Tulip"
    family = "None"
    hacker = "None"
    hash1 = "4c2fc21a4aab7686877ddd35d74a917f6156e48117920d45a3d2f21fb74fedd3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.clearskysec.com/tulip"
    threatname = "None"
    threattype = "None"
  strings:
    $r1 = "<Command>C:\\Windows\\syswow64\\rundll32.exe</Command>" fullword wide
    $p1 = "<Arguments>\"C:\\Users\\public\\" wide
    $c1 = "svchost64.swp\",checkUpdate" wide ascii
    $c2 = "svchost64.swp,checkUpdate" wide ascii
  condition:
    ( $r1 and $p1 ) or
    1 of ($c*)
}