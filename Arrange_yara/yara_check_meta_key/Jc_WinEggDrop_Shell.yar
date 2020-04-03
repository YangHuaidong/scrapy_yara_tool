rule Jc_WinEggDrop_Shell {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file Jc.WinEggDrop Shell.txt"
    family = "None"
    hacker = "None"
    hash = "820674b59f32f2cf72df50ba4411d7132d863ad2"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Sniffer.dll" fullword ascii
    $s4 = ":Execute net.exe user Administrator pass" fullword ascii
    $s5 = "Fport.exe or mport.exe " fullword ascii
    $s6 = ":Password Sniffering Is Running |Not Running " fullword ascii
    $s9 = ": The Terminal Service Port Has Been Set To NewPort" fullword ascii
    $s15 = ": Del www.exe                   " fullword ascii
    $s20 = ":Dir *.exe                    " fullword ascii
  condition:
    2 of them
}