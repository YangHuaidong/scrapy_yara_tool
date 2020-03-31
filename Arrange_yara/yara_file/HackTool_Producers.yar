rule HackTool_Producers {
   meta:
      description = "Hacktool Producers String"
      threat_level = 5
      score = 50
      nodeepdive = 1
   strings:
      $a1 = "www.oxid.it"
      $a2 = "www.analogx.com"
      $a3 = "ntsecurity.nu"
      $a4 = "gentilkiwi.com"
      $a6 = "Marcus Murray"
      $a7 = "Nsasoft US LLC0"
      $a8 = " Nir Sofer"
   condition:
      uint16(0) == 0x5a4d and 1 of ($a*) and
      not extension contains ".ini" and
      not extension contains ".xml" and
      not extension contains ".sqlite"
}