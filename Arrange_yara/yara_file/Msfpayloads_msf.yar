rule Msfpayloads_msf {
   meta:
      description = "Metasploit Payloads - file msf.sh"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09"
      hash1 = "320a01ec4e023fb5fbbaef963a2b57229e4f918847e5a49c7a3f631cb556e96c"
   strings:
      $s1 = "export buf=\\" fullword ascii
   condition:
      ( uint16(0) == 0x7865 and filesize < 4KB and ( 10 of ($s*) ) ) or ( all of them )
}