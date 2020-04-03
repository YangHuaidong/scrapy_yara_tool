rule PAS_Webshell_Encoded {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-11"
    description = "Detects a PAS webshell"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://blog.talosintelligence.com/2017/07/the-medoc-connection.html"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $head1 = "<?php $____=" fullword ascii
    $head2 = "'base'.(32*2).'"
    $enc1 = "isset($_COOKIE['___']" ascii
    $enc2 = "if($___!==NULL){" ascii
    $enc3 = ").substr(md5(strrev($" ascii
    $enc4 = "]))%256);$" ascii
    $enc5 = "]))@setcookie('" ascii
    $enc6 = "]=chr(( ord($_" ascii
    /* = \x0A'));if(isset($_COOKIE[' */
    $x1 = { 3d 0a 27 29 29 3b 69 66 28 69 73 73 65 74 28 24 5f 43 4f 4f 4b 49 45 5b 27 }
    $foot1 = "value=\"\"/><input type=\"submit\" value=\"&gt;\"/></form>"
    $foot2 = "();}} @header(\"Status: 404 Not Found\"); ?>"
  condition:
    ( uint32(0) == 0x68703f3c and filesize < 80KB and (
    3 of them or
    $head1 at 0 or
    $head2 in (0..20) or
    1 of ($x*)
    ) or
    $foot1 at (filesize-52) or
    $foot2 at (filesize-44)
}