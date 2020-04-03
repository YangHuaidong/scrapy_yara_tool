rule Sharpire {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-09-23"
    description = "Auto-generated rule - file Sharpire.exe"
    family = "None"
    hacker = "None"
    hash1 = "327a1dc2876cd9d7f6a5b3777373087296fc809d466e42861adcf09986c6e587"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/0xbadjuju/Sharpire"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "\\obj\\Debug\\Sharpire.pdb" fullword ascii
    $x2 = "[*] Upload of $fileName successful" fullword wide
    $s1 = "no shell command supplied" fullword wide
    $s2 = "/login/process.php" fullword wide
    $s3 = "invokeShellCommand" fullword ascii
    $s4 = "..Command execution completed." fullword wide
    $s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword wide
    $s6 = "/admin/get.php" fullword wide
    $s7 = "[!] Error in stopping job: " fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of ($x*) and 3 of them ) )
}