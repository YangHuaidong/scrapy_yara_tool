rule APT_Kaspersky_Duqu2_procexp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-10"
    description = "Kaspersky APT Report - Duqu2 Sample - Malicious MSI"
    family = "None"
    hacker = "None"
    hash1 = "2422835716066b6bcecb045ddd4f1fbc9486667a"
    hash2 = "b120620b5d82b05fee2c2153ceaf305807fa9f79"
    hash3 = "288ebfe21a71f83b5575dfcc92242579fb13910d"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/7yKyOj"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "svcmsi_32.dll" fullword wide
    $x2 = "msi3_32.dll" fullword wide
    $x3 = "msi4_32.dll" fullword wide
    $x4 = "MSI.dll" fullword ascii
    $s1 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" fullword wide
    $s2 = "Sysinternals installer" fullword wide /* PEStudio Blacklist: strings */
    $s3 = "Process Explorer" fullword wide /* PEStudio Blacklist: strings */ /* Goodware String - occured 5 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of ($x*) ) and ( all of ($s*) )
}