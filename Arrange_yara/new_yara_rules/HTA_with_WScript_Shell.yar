rule HTA_with_WScript_Shell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-21"
    description = "Detects WScript Shell in HTA"
    family = "None"
    hacker = "None"
    hash1 = "ca7b653cf41e980c44311b2cd701ed666f8c1dbc"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/msftmmpc/status/877396932758560768"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<hta:application windowstate=\"minimize\"/>"
    $s2 = "<script>var b=new ActiveXObject(\"WScript.Shell\");" ascii
  condition:
    all of them
}