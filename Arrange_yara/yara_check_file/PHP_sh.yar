rule PHP_sh {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file sh.php
    family = None
    hacker = None
    hash = 1e9e879d49eb0634871e9b36f99fe528
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = PHP[sh
    threattype = sh.yar
  strings:
    $s1 = "\"@$SERVER_NAME \".exec(\"pwd\")"
  condition:
    all of them
}