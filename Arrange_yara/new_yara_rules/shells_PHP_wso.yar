rule shells_PHP_wso {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file wso.txt"
    family = "None"
    hacker = "None"
    hash = "33e2891c13b78328da9062fbfcf898b6"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$back_connect_p=\"IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbi"
    $s3 = "echo '<h1>Execution PHP-code</h1><div class=content><form name=pf method=pos"
  condition:
    1 of them
}