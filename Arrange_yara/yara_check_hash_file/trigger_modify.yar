rule trigger_modify {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file trigger_modify.php
    family = None
    hacker = None
    hash = c93cd7a6c3f962381e9bf2b511db9b1639a22de0
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = trigger[modify
    threattype = modify.yar
  strings:
    $s1 = "<form name=\"form1\" method=\"post\" action=\"trigger_modify.php?trigger=<?php e" ascii
    $s2 = "$data_query = @mssql_query('sp_helptext \\'' . urldecode($_GET['trigger']) . '" ascii
    $s3 = "if($_POST['query'] != '')" fullword ascii
    $s4 = "$lines[] = 'I am unable to read this trigger.';" fullword ascii
    $s5 = "<b>Modify Trigger</b>" fullword ascii
  condition:
    filesize < 15KB and all of them
}