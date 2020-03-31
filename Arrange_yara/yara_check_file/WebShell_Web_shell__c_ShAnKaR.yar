rule WebShell_Web_shell__c_ShAnKaR {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file Web-shell (c)ShAnKaR.php
    family = 
    hacker = None
    hash = 3dd4f25bd132beb59d2ae0c813373c9ea20e1b7a
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[Web]/shell..c.ShAnKaR
    threattype = Web
  strings:
    $s0 = "header(\"Content-Length: \".filesize($_POST['downf']));" fullword
    $s5 = "if($_POST['save']==0){echo \"<textarea cols=70 rows=10>\".htmlspecialchars($dump"
    $s6 = "write(\"#\\n#Server : \".getenv('SERVER_NAME').\"" fullword
    $s12 = "foreach(@file($_POST['passwd']) as $fed)echo $fed;" fullword
  condition:
    2 of them
}