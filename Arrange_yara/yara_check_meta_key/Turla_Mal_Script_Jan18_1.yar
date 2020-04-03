rule Turla_Mal_Script_Jan18_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-01-19"
    description = "Detects Turla malicious script"
    family = "None"
    hacker = "None"
    hash1 = "180b920e9cea712d124ff41cd1060683a14a79285d960e17f0f49b969f15bfcc"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://ghostbin.com/paste/jsph7"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = ".charCodeAt(i % " ascii
    $s2 = "{WScript.Quit();}" fullword ascii
    $s3 = ".charAt(i)) << 10) |" ascii
    $s4 = " = WScript.Arguments;var " ascii
    $s5 = "= \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";var i;" ascii
  condition:
    filesize < 200KB and 2 of them
}