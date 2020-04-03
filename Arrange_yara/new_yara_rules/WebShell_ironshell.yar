rule WebShell_ironshell {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file ironshell.php"
    family = "None"
    hacker = "None"
    hash = "d47b8ba98ea8061404defc6b3a30839c4444a262"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<title>'.getenv(\"HTTP_HOST\").' ~ Shell I</title>" fullword
    $s2 = "$link = mysql_connect($_POST['host'], $_POST['username'], $_POST"
    $s4 = "error_reporting(0); //If there is an error, we'll show it, k?" fullword
    $s8 = "print \"<form action=\\\"\".$me.\"?p=chmod&file=\".$content.\"&d"
    $s15 = "if(!is_numeric($_POST['timelimit']))" fullword
    $s16 = "if($_POST['chars'] == \"9999\")" fullword
    $s17 = "<option value=\\\"az\\\">a - zzzzz</option>" fullword
    $s18 = "print shell_exec($command);" fullword
  condition:
    3 of them
}