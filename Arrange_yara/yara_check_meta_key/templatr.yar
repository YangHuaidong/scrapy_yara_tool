rule templatr {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file templatr.php"
    family = "None"
    hacker = "None"
    hash = "759df470103d36a12c7d8cf4883b0c58fe98156b"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "eval(gzinflate(base64_decode('" ascii
  condition:
    filesize < 70KB and all of them
}