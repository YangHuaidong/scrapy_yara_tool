rule Locky_Ransomware {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-02-17"
    description = "Detects Locky Ransomware (matches also on Win32/Kuluoz)"
    family = "None"
    hacker = "None"
    hash = "5e945c1d27c9ad77a2b63ae10af46aee7d29a6a43605a9bfbf35cebbcff184d8"
    judge = "unknown"
    reference = "https://goo.gl/qScSrE"
    threatname = "None"
    threattype = "None"
  strings:
    $o1 = { 45 b8 99 f7 f9 0f af 45 b8 89 45 b8 } // address=0x4144a7
    $o2 = { 2b 0a 0f af 4d f8 89 4d f8 c7 45 } // address=0x413863
  condition:
    all of ($o*)
}