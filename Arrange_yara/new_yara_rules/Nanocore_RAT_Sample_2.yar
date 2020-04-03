rule Nanocore_RAT_Sample_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-04-22"
    description = "Detetcs a certain Nanocore RAT sample"
    family = "None"
    hacker = "None"
    hash1 = "51142d1fb6c080b3b754a92e8f5826295f5da316ec72b480967cbd68432cede1"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "U4tSOtmpM" fullword ascii
    $s2 = ")U71UDAU_QU_YU_aU_iU_qU_yU_" fullword wide
    $s3 = "Cy4tOtTmpMtTHVFOrR" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 40KB and all of ($s*)
}