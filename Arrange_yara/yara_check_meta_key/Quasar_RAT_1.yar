rule Quasar_RAT_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-07"
    description = "Detects Quasar RAT"
    family = "None"
    hacker = "None"
    hash1 = "0774d25e33ca2b1e2ee2fafe3fdbebecefbf1d4dd99e6460f0bc8713dd0fd740"
    hash2 = "1ce40a89ef9d56fd32c00db729beecc17d54f4f7c27ff22f708a957cd3f9a4ec"
    hash3 = "515c1a68995557035af11d818192f7866ef6a2018aa13112fefbe08395732e89"
    hash4 = "f08db220df716de3d4f63f3007a03f902601b9b32099d6a882da87312f263f34"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "DoUploadAndExecute" fullword ascii
    $s2 = "DoDownloadAndExecute" fullword ascii
    $s3 = "DoShellExecute" fullword ascii
    $s4 = "set_Processname" fullword ascii
    $op1 = { 04 1e fe 02 04 16 fe 01 60 }
    $op2 = { 00 17 03 1f 20 17 19 15 28 }
    $op3 = { 00 04 03 69 91 1b 40 }
  condition:
    ( uint16(0) == 0x5a4d and filesize < 5000KB and all of ($s*) or all of ($op*) )
}