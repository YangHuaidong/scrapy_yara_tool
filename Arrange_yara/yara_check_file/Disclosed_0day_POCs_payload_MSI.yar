rule Disclosed_0day_POCs_payload_MSI {
  meta:
    author = Spider
    comment = None
    date = 2017-07-07
    description = Detects POC code from disclosed 0day hacktool set
    family = payload
    hacker = None
    hash1 = a7c498a95850e186b7749a96004a98598f45faac2de9b93354ac93e627508a87
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed 0day Repos
    threatname = Disclosed[0day]/POCs.payload.MSI
    threattype = 0day
  strings:
    $s1 = "WShell32.dll" fullword wide
    $s2 = "Target empty, so account name translation begins on the local system." fullword wide
    $s3 = "\\custact\\x86\\AICustAct.pdb" fullword ascii
  condition:
    ( uint16(0) == 0xcfd0 and filesize < 1000KB and all of them )
}