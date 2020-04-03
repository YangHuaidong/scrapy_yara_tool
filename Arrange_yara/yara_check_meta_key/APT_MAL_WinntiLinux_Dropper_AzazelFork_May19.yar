rule APT_MAL_WinntiLinux_Dropper_AzazelFork_May19 : azazel_fork {
  meta:
    TLP = "White"
    author = "Spider"
    comment = "None"
    date = "2019-05-15"
    description = "Detection of Linux variant of Winnti"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    sha256 = "4741c2884d1ca3a40dadd3f3f61cb95a59b11f99a0f980dbadc663b85eb77a2a"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $config_decr = { 48 89 45 f0 c7 45 ec 08 01 00 00 c7 45 fc 28 00 00 00 eb 31 8b 45 fc 48 63 d0 48 8b 45 f0 48 01 c2 8b 45 fc 48 63 c8 48 8b 45 f0 48 01 c8 0f b6 00 89 c1 8b 45 f8 89 c6 8b 45 fc 01 f0 31 c8 88 02 83 45 fc 01 }
    $export1 = "our_sockets"
    $export2 = "get_our_pids"
  condition:
    uint16(0) == 0x457f and all of them
}