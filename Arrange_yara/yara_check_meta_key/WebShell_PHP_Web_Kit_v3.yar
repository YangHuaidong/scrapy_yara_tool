rule WebShell_PHP_Web_Kit_v3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016/01/01"
    description = "Detects PAS Tool PHP Web Kit"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/wordfence/grizzly"
    threatname = "None"
    threattype = "None"
  strings:
    $php = "<?php $"
    $php2 = "@assert(base64_decode($_REQUEST["
    $s1 = "(str_replace(\"\\n\", '', '"
    $s2 = "(strrev($" ascii
    $s3 = "de'.'code';" ascii
  condition:
    ( ( uint32(0) == 0x68703f3c and $php at 0 ) or $php2 ) and
    filesize > 8KB and filesize < 100KB and
    all of ($s*)
}