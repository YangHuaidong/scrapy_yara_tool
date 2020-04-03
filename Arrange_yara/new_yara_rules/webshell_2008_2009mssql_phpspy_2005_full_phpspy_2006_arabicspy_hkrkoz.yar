rule webshell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell"
    family = "None"
    hacker = "None"
    hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
    hash1 = "aa17b71bb93c6789911bd1c9df834ff9"
    hash2 = "b68bfafc6059fd26732fa07fb6f7f640"
    hash3 = "40a1f840111996ff7200d18968e42cfe"
    hash4 = "e0202adff532b28ef1ba206cf95962f2"
    hash5 = "802f5cae46d394b297482fd0c27cb2fc"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$this -> addFile($content, $filename);" fullword
    $s3 = "function addFile($data, $name, $time = 0) {" fullword
    $s8 = "function unix2DosTime($unixtime = 0) {" fullword
    $s9 = "foreach($filelist as $filename){" fullword
  condition:
    all of them
}