rule PAS_TOOL_PHP_WEB_KIT_mod {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016/12/29"
    description = "Detects PAS Tool PHP Web Kit"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/security-publications/GRIZZLY-STEPPE-Russian-Malicious-Cyber-Activity"
    threatname = "None"
    threattype = "None"
  strings:
    $php = "<?php"
    $base64decode1 = "='base'.("
    $strreplace = "str_replace(\"\\n\", ''"
    $md5 = ".substr(md5(strrev("
    $gzinflate = "gzinflate"
    $cookie = "_COOKIE"
    $isset = "isset"
  condition:
    uint32(0) == 0x68703f3c and
    $php at 0 and
    (filesize > 10KB and filesize < 30KB) and
    #cookie == 2 and
    #isset == 3 and
    all of them
}