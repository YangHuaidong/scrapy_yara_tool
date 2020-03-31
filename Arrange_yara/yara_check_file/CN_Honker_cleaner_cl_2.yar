rule CN_Honker_cleaner_cl_2 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file cl.exe
    family = cl
    hacker = None
    hash = 523084e8975b16e255b56db9af0f9eecf174a2dd
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/cleaner.cl.2
    threattype = Honker
  strings:
    $s0 = "cl -eventlog All/Application/System/Security" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "clear iislog error!" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 50KB and all of them
}