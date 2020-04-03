rule CN_Honker_ASP_wshell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file wshell.txt"
    family = "None"
    hacker = "None"
    hash = "3ae33c835e7ea6d9df74fe99fcf1e2fb9490c978"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "UserPass="
    $s2 = "VerName="
    $s3 = "StateName="
  condition:
    uint16(0) == 0x253c and filesize < 200KB and all of them
}