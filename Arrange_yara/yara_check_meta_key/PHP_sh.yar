rule PHP_sh {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file sh.php"
    family = "None"
    hacker = "None"
    hash = "1e9e879d49eb0634871e9b36f99fe528"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\"@$SERVER_NAME \".exec(\"pwd\")"
  condition:
    all of them
}