rule webshell_php_dodo_zip {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file zip.php
    family = zip
    hacker = None
    hash = b7800364374077ce8864796240162ad5
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[php]/dodo.zip
    threattype = php
  strings:
    $s0 = "$hexdtime = '\\x' . $dtime[6] . $dtime[7] . '\\x' . $dtime[4] . $dtime[5] . '\\x"
    $s3 = "$datastr = \"\\x50\\x4b\\x03\\x04\\x0a\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
  condition:
    all of them
}