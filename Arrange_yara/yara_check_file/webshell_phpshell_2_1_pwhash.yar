rule webshell_phpshell_2_1_pwhash {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file pwhash.php
    family = 1
    hacker = None
    hash = ba120abac165a5a30044428fac1970d8
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[phpshell]/2.1.pwhash
    threattype = phpshell
  strings:
    $s1 = "<tt>&nbsp;</tt>\" (space), \"<tt>[</tt>\" (left bracket), \"<tt>|</tt>\" (pi"
    $s3 = "word: \"<tt>null</tt>\", \"<tt>yes</tt>\", \"<tt>no</tt>\", \"<tt>true</tt>\","
  condition:
    1 of them
}