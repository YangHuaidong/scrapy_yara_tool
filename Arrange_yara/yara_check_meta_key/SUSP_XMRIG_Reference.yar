rule SUSP_XMRIG_Reference {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-06-20"
    description = "Detects an executable with a suspicious XMRIG crypto miner reference"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://twitter.com/itaitevet/status/1141677424045953024"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "\\xmrig\\" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}