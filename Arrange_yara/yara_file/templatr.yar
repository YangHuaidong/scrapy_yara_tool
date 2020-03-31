rule templatr {
    meta:
        description = "Chinese Hacktool Set - file templatr.php"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "759df470103d36a12c7d8cf4883b0c58fe98156b"
    strings:
        $s0 = "eval(gzinflate(base64_decode('" ascii
    condition:
        filesize < 70KB and all of them
}