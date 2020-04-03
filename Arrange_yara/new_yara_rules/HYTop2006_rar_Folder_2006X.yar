rule HYTop2006_rar_Folder_2006X {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file 2006X.exe"
    family = "None"
    hacker = "None"
    hash = "cf3ee0d869dd36e775dfcaa788db8e4b"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<input name=\"password\" type=\"password\" id=\"password\""
    $s6 = "name=\"theAction\" type=\"text\" id=\"theAction\""
  condition:
    all of them
}