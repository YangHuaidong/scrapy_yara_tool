rule APT_DarkHydrus_Jul18_5 {
   meta:
      description = "Detects strings found in malware samples in APT report in DarkHydrus"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28"
      hash1 = "cec36e8ed65ac6f250c05b4a17c09f58bb80c19b73169aaf40fa15c8d3a9a6a1"
   strings:
      $s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii
      $s2 = "libgcj-12.dll" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and (
         pe.imphash() == "829da329ce140d873b4a8bde2cbfaa7e" or
         all of them
      )
}