rule CN_Honker_no_net_priv_esc_AddUser {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file AddUser.dll
    family = net
    hacker = None
    hash = 4c95046be6ae40aee69a433e9a47f824598db2d4
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/no.net.priv.esc.AddUser
    threattype = Honker
  strings:
    $s0 = "PECompact2" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "adduser" fullword ascii
    $s5 = "OagaBoxA" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 115KB and all of them
}