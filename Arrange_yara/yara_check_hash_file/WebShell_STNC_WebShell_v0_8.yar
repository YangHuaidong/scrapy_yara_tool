rule WebShell_STNC_WebShell_v0_8 {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file STNC WebShell v0.8.php
    family = v0
    hacker = None
    hash = 52068c9dff65f1caae8f4c60d0225708612bb8bc
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[STNC]/WebShell.v0.8
    threattype = STNC
  strings:
    $s3 = "if(isset($_POST[\"action\"])) $action = $_POST[\"action\"];" fullword
    $s8 = "elseif(fe(\"system\")){ob_start();system($s);$r=ob_get_contents();ob_end_clean()"
    $s13 = "{ $pwd = $_POST[\"pwd\"]; $type = filetype($pwd); if($type === \"dir\")chdir($pw"
  condition:
    2 of them
}