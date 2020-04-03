rule HKTL_PowerSploit {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-06-23"
    description = "Detects default strings used by PowerSploit to establish persistence"
    family = "None"
    hacker = "None"
    hash1 = "16937e76db6d88ed0420ee87317424af2d4e19117fe12d1364fee35aa2fadb75"
    judge = "black"
    reference = "https://www.hybrid-analysis.com/sample/16937e76db6d88ed0420ee87317424af2d4e19117fe12d1364fee35aa2fadb75?environmentId=100" /*MuddyWater*/"
    threatname = "None"
    threattype = "None"
  strings:
    $ps = "function" nocase ascii wide
    $s1 = "/Create /RU system /SC ONLOGON" ascii wide
    $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
  condition:
    all of them
}