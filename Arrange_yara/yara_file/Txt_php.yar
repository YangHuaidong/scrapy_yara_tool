rule Txt_php {
    meta:
        description = "Chinese Hacktool Set - Webshells - file php.txt"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "eaa1af4b898f44fc954b485d33ce1d92790858d0"
    strings:
        $s1 = "$Config=$_SERVER['QUERY_STRING'];" fullword ascii
        $s2 = "gzuncompress($_SESSION['api']),null);" ascii
        $s3 = "sprintf('%s?%s',pack(\"H*\"," ascii
        $s4 = "if(empty($_SESSION['api']))" fullword ascii
    condition:
        filesize < 1KB and all of them
}