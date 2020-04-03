rule RAT_HawkEye {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.06.2015"
    description = "Detects HawkEye RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "KeyLogger"
    reference = "http://malwareconfig.com/stats/HawkEye"
    threatname = "None"
    threattype = "None"
  strings:
    $key = "HawkEyeKeylogger" wide
    $salt = "099u787978786" wide
    $string1 = "HawkEye_Keylogger" wide
    $string2 = "holdermail.txt" wide
    $string3 = "wallet.dat" wide
    $string4 = "Keylog Records" wide
    $string5 = "<!-- do not script -->" wide
    $string6 = "\\pidloc.txt" wide
    $string7 = "BSPLIT" wide
  condition:
    $key and $salt and all of ($string*)
}