rule CN_Honker_MSTSC_can_direct_copy {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file MSTSC_can_direct_copy.EXE
    family = can
    hacker = None
    hash = 2f3cbfd9f82f8abafdb1d33235fa6bfa1e1f71ae
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/MSTSC.can.direct.copy
    threattype = Honker
  strings:
    $s1 = "srv\\newclient\\lib\\win32\\obj\\i386\\mstsc.pdb" fullword ascii
    $s2 = "Clear Password" fullword wide /* PEStudio Blacklist: strings */
    $s3 = "/migrate -- migrates legacy connection files that were created with " fullword wide /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 600KB and all of them
}