rule EquationGroup__ftshell_ftshell_v3_10_3_0 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files ftshell, ftshell.v3.10.3.7"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash1 = "9bebeb57f1c9254cb49976cc194da4be85da4eb94475cb8d813821fb0b24f893"
      hash2 = "0be739024b41144c3b63e40e46bab22ac098ccab44ab2e268efc3b63aea02951"
   strings:
      $s1 = "set uRemoteUploadCommand \"[exec cat /current/.ourtn-ftshell-upcommand]\"" fullword ascii
      $s2 = "send \"\\[ \\\"\\$BASH\\\" = \\\"/bin/bash\\\" -o \\\"\\$SHELL\\\" = \\\"/bin/bash\\\" \\] &&" ascii
      $s3 = "system rm -f /current/tmp/ftshell.latest" fullword ascii
      $s4 = "# ftshell -- File Transfer Shell" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 100KB and 1 of them ) or ( 2 of them )
}