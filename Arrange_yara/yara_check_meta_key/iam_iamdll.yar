rule iam_iamdll {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-07-10"
    description = "Auto-generated rule - file iamdll.dll"
    family = "None"
    hacker = "None"
    hash = "892de92f71941f7b9e550de00a57767beb7abe1171562e29428b84988cee6602"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "LSASRV.DLL" fullword ascii /* score: '21.00' */
    $s1 = "iamdll.dll" fullword ascii /* score: '21.00' */
    $s2 = "ChangeCreds" fullword ascii /* score: '12.00' */
  condition:
    uint16(0) == 0x5a4d and filesize < 115KB and all of them
}