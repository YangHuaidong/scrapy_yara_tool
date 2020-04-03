rule PowerShell_ISESteroids_Obfuscation {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-23"
    description = "Detects PowerShell ISESteroids obfuscation"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/danielhbohannon/status/877953970437844993"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "/\\/===\\__" ascii
    $x2 = "${__/\\/==" ascii
    $x3 = "Catch { }" fullword ascii
    $x4 = "\\_/=} ${_" ascii
  condition:
    2 of them
}