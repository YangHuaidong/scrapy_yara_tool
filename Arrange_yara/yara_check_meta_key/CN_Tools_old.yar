rule CN_Tools_old {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file old.php"
    family = "None"
    hacker = "None"
    hash = "f8a007758fda8aa1c0af3c43f3d7e3186a9ff307"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
    $s1 = "$sURL = \"http://\".$sServer.\"/\".$sFile;" fullword ascii
    $s2 = "chmod(\"/\".substr($sHash, 0, 2), 0777);" fullword ascii
    $s3 = "$sCmd = \"echo 123> \".$sFileOut;" fullword ascii
  condition:
    filesize < 6KB and all of them
}