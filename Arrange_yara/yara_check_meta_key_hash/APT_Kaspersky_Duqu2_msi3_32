rule APT_Kaspersky_Duqu2_msi3_32 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-10"
    description = "Kaspersky APT Report - Duqu2 Sample - file d8a849654ab97debaf28ae5b749c3b1ff1812ea49978713853333db48c3972c3"
    family = "None"
    hacker = "None"
    hash = "53d9ef9e0267f10cc10f78331a9e491b3211046b"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/7yKyOj"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "ProcessUserAccounts" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "SELECT `UserName`, `Password`, `Attributes` FROM `CustomUserAccounts`" fullword wide /* PEStudio Blacklist: strings */
    $s2 = "SELECT `UserName` FROM `CustomUserAccounts`" fullword wide /* PEStudio Blacklist: strings */
    $s3 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" fullword wide
    $s4 = "msi3_32.dll" fullword wide
    $s5 = "RunDLL" fullword ascii
    $s6 = "MSI Custom Action v3" fullword wide
    $s7 = "msi3_32" fullword wide
    $s8 = "Operating System" fullword wide /* PEStudio Blacklist: strings */ /* Goodware String - occured 9203 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 72KB and all of them
}