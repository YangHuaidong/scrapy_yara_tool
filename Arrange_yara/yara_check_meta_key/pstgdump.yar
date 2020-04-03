rule pstgdump {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-09-08"
    description = "Detects a tool used by APT groups - file pstgdump.exe"
    family = "None"
    hacker = "None"
    hash1 = "65d48a2f868ff5757c10ed796e03621961954c523c71eac1c5e044862893a106"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/igxLyF"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "\\Release\\pstgdump.pdb" ascii
    $x2 = "Failed to dump all protected storage items - see previous messages for details" fullword ascii
    $x3 = "ptsgdump [-h][-q][-u Username][-p Password]" fullword ascii
    $x4 = "Attempting to impersonate domain user '%s' in domain '%s'" fullword ascii
    $x5 = "Failed to impersonate user (ImpersonateLoggedOnUser failed): error %d" fullword ascii
    $x6 = "Unable to obtain handle to PStoreCreateInstance in pstorec.dll" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of ($x*) ) or ( 3 of them )
}