rule MooreR_Port_Scanner {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule on file MooreR Port Scanner.exe"
    family = "None"
    hacker = "None"
    hash = "376304acdd0b0251c8b19fea20bb6f5b"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Description|"
    $s3 = "soft Visual Studio\\VB9yp"
    $s4 = "adj_fptan?4"
    $s7 = "DOWS\\SyMem32\\/o"
  condition:
    all of them
}