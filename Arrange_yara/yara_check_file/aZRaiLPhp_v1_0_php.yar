rule aZRaiLPhp_v1_0_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file aZRaiLPhp v1.0.php.txt
    family = php
    hacker = None
    hash = 26b2d3943395682e36da06ed493a3715
    judge = unknown
    reference = None
    threatname = aZRaiLPhp[v1]/0.php
    threattype = v1
  strings:
    $s0 = "azrailphp"
    $s1 = "<br><center><INPUT TYPE='SUBMIT' NAME='dy' VALUE='Dosya Yolla!'></center>"
    $s3 = "<center><INPUT TYPE='submit' name='okmf' value='TAMAM'></center>"
  condition:
    2 of them
}