rule APT_apt_duqu2_drivers {
  meta:
    author = "Spider"
    comment = "None"
    copyright = "Kaspersky Lab"
    date = "None"
    description = "Rule to detect Duqu 2.0 drivers"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2015-06-09"
    reference = "None"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $a1 = "\\DosDevices\\port_optimizer" wide nocase
    $a2 = "romanian.antihacker"
    $a3 = "PortOptimizerTermSrv" wide
    $a4 = "ugly.gorilla1"
    $b1 = "NdisIMCopySendCompletePerPacketInfo"
    $b2 = "NdisReEnumerateProtocolBindings"
    $b3 = "NdisOpenProtocolConfiguration"
  condition:
    uint16(0) == 0x5A4D and (any of ($a*) ) and (2 of ($b*)) and filesize < 100000
}