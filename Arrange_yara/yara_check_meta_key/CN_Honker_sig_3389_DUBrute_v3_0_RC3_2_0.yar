rule CN_Honker_sig_3389_DUBrute_v3_0_RC3_2_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file 2.0.exe"
    family = "None"
    hacker = "None"
    hash = "e8ee982421ccff96121ffd24a3d84e3079f3750f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "IP - %d; Login - %d; Password - %d; Combination - %d" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "Create %d IP@Loginl;Password" fullword ascii /* PEStudio Blacklist: strings */
    $s15 = "UBrute.com" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 980KB and 2 of them
}