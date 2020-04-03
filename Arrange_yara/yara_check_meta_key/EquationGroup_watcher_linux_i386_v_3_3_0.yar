rule EquationGroup_watcher_linux_i386_v_3_3_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-09"
    description = "Equation Group hack tool set"
    family = "None"
    hacker = "None"
    hash1 = "ce4c9bfa25b8aad8ea68cc275187a894dec5d79e8c0b2f2f3ec4184dc5f402b8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "invalid option `" fullword ascii
    $s8 = "readdir64" fullword ascii
    $s9 = "89:z89:%r%opw" fullword wide
    $s13 = "Ropopoprstuvwypypop" fullword wide
    $s17 = "Missing argument for `-x'." fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 700KB and all of them )
}