rule EquationGroup_Toolset_Apr17_Iistouch_1_2_2 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c433507d393a8aa270576790acb3e995e22f4ded886eb9377116012e247a07c6"
   strings:
      $x1 = "[-] Are you being redirectect? Need to retarget?" fullword ascii
      $x2 = "[+] IIS Target OS: %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 60KB and 1 of them )
}