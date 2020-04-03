rule APT_WebShell_AUS_Tiny_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-02-18"
    description = "Detetcs a tiny webshell involved in the Australian Parliament House network compromise"
    family = "None"
    hacker = "None"
    hash1 = "0d6209d86f77a0a69451b0f27b476580c14e0cda15fa6a5003aab57a93e7e5a5"
    judge = "unknown"
    reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Request.Item[System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(\"[password]\"))];" ascii
    $x2 = "eval(arguments,System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(\"" ascii
  condition:
    ( uint16(0) == 0x3f3c or uint16(0) == 0x253c ) and filesize < 1KB and 1 of them
}