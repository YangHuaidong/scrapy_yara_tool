rule ChinaChopper_temp_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file temp.php"
    family = "None"
    hacker = "None"
    hash = "604a4c07161ce1cd54aed5566e5720161b59deee"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "@eval($_POST[strtoupper(md5(gmdate(" ascii
  condition:
    filesize < 150 and all of them
}