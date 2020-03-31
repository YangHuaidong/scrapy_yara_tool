rule sig_2008_php_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file 2008.php.php.txt
    family = php
    hacker = None
    hash = 3e4ba470d4c38765e4b16ed930facf2c
    judge = unknown
    reference = None
    threatname = sig[2008]/php.php
    threattype = 2008
  strings:
    $s0 = "Codz by angel(4ngel)"
    $s1 = "Web: http://www.4ngel.net"
    $s2 = "$admin['cookielife'] = 86400;"
    $s3 = "$errmsg = 'The file you want Downloadable was nonexistent';"
  condition:
    1 of them
}