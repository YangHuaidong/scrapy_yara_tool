rule phpshell_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file phpshell.php"
    family = "None"
    hacker = "None"
    hash = "e8693a2d4a2ffea4df03bb678df3dc6d"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>"
    $s5 = "      echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";"
  condition:
    all of them
}