rule CN_Honker_SQLServer_inject_Creaked {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file SQLServer_inject_Creaked.exe
    family = inject
    hacker = None
    hash = af3c41756ec8768483a4cf59b2e639994426e2c2
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/SQLServer.inject.Creaked
    threattype = Honker
  strings:
    $s1 = "http://localhost/index.asp?id=2" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "Email:zhaoxypass@yahoo.com.cn<br>" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 8110KB and all of them
}