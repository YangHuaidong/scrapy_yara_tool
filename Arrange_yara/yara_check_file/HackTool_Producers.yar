rule HackTool_Producers {
  meta:
    author = Spider
    comment = None
    date = None
    description = Hacktool Producers String
    family = None
    hacker = None
    judge = unknown
    nodeepdive = 1
    reference = None
    score = 50
    threat_level = 5
    threatname = HackTool[Producers
    threattype = Producers.yar
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