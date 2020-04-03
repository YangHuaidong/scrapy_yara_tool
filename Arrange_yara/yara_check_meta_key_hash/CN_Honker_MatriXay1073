rule CN_Honker_MatriXay1073 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file MatriXay1073.exe"
    family = "None"
    hacker = "None"
    hash = "fef951e47524f827c7698f4508ba9551359578a5"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1" ascii /* PEStudio Blacklist: strings */
    $s1 = "Policy\\Scan\\GetUserLen.ini" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "!YEL!Using http://127.0.0.1:%d/ to visiter https://%s:%d/" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "getalluserpasswordhash" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 9100KB and all of them
}