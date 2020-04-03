rule oracle_data {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file oracle_data.php"
    family = "None"
    hacker = "None"
    hash = "6cf070017be117eace4752650ba6cf96d67d2106"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$txt=fopen(\"oracle_info.txt\",\"w\");" fullword ascii
    $s1 = "if(isset($_REQUEST['id']))" fullword ascii
    $s2 = "$id=$_REQUEST['id'];" fullword ascii
  condition:
    all of them
}