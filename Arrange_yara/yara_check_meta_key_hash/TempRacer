rule TempRacer {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-03-30"
    description = "Detects privilege escalation tool - file TempRacer.exe"
    family = "None"
    hacker = "None"
    hash = "e17d80c4822d16371d75e1440b6ac44af490b71fbee1010a3e8a5eca94d22bb3"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.darknet.org.uk/2016/03/tempracer-windows-privilege-escalation-tool/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\obj\\Release\\TempRacer.pdb" ascii
    $s2 = "[+] Injecting into " fullword wide
    $s3 = "net localgroup administrators alex /add" fullword wide
    $s4 = "[+] File: {0} renamed to {1}" fullword wide
    $s5 = "[+] Blocking " fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 25KB and 1 of them ) or ( 4 of them )
}