rule webshell_wso2_5_1_wso2_5_wso2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files wso2.5.1.php, wso2.5.php, wso2.php"
    family = "None"
    hacker = "None"
    hash0 = "dbeecd555a2ef80615f0894027ad75dc"
    hash1 = "7c8e5d31aad28eb1f0a9a53145551e05"
    hash2 = "cbc44fb78220958f81b739b493024688"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s7 = "$opt_charsets .= '<option value=\"'.$item.'\" '.($_POST['charset']==$item?'selec"
    $s8 = ".'</td><td><a href=\"#\" onclick=\"g(\\'FilesTools\\',null,\\''.urlencode($f['na"
  condition:
    all of them
}