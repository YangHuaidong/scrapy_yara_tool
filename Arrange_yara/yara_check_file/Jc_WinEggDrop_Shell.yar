rule Jc_WinEggDrop_Shell {
   meta:
      description = "Disclosed hacktool set (old stuff) - file Jc.WinEggDrop Shell.txt"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "23.11.14"
      score = 60
      hash = "820674b59f32f2cf72df50ba4411d7132d863ad2"
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