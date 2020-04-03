rule webshell_shell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell"
    family = "None"
    hacker = "None"
    hash0 = "791708057d8b429d91357d38edf43cc0"
    hash1 = "3e4ba470d4c38765e4b16ed930facf2c"
    hash2 = "aa17b71bb93c6789911bd1c9df834ff9"
    hash3 = "b68bfafc6059fd26732fa07fb6f7f640"
    hash4 = "40a1f840111996ff7200d18968e42cfe"
    hash5 = "e0202adff532b28ef1ba206cf95962f2"
    hash6 = "802f5cae46d394b297482fd0c27cb2fc"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$tabledump .= \"'\".mysql_escape_string($row[$fieldcounter]).\"'\";" fullword
    $s5 = "while(list($kname, $columns) = @each($index)) {" fullword
    $s6 = "$tabledump = \"DROP TABLE IF EXISTS $table;\\n\";" fullword
    $s9 = "$tabledump .= \"   PRIMARY KEY ($colnames)\";" fullword
    $fn = "filename: backup"
  condition:
    2 of ($s*) and not $fn
}