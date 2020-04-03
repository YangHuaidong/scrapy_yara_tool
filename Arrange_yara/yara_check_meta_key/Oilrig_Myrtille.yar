rule Oilrig_Myrtille {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-03-22"
    description = "Detects Oilrig Myrtille RDP Browser"
    family = "None"
    hacker = "None"
    hash1 = "67945f2e65a4a53e2339bd361652c6663fe25060888f18e681418e313d1292ca"
    judge = "black"
    reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "\\obj\\Release\\Myrtille.Services.pdb" fullword ascii
    $x2 = "Failed to notify rdp client process exit (MyrtilleAppPool down?), remote session {0} ({1})" fullword wide
    $x3 = "Started rdp client process, remote session {0}" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 50KB and 1 of them
}