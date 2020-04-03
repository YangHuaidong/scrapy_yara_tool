rule trigger_drop {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file trigger_drop.php"
    family = "None"
    hacker = "None"
    hash = "165dd2d82bf87285c8a53ad1ede6d61a90837ba4"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$_GET['returnto'] = 'database_properties.php';" fullword ascii
    $s1 = "echo('<meta http-equiv=\"refresh\" content=\"0;url=' . $_GET['returnto'] . '\">'" ascii
    $s2 = "@mssql_query('DROP TRIGGER" ascii
    $s3 = "if(empty($_GET['returnto']))" fullword ascii
  condition:
    filesize < 5KB and all of them
}