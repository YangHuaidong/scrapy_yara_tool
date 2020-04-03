rule webshell_PHP_c37 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file c37.php"
    family = "None"
    hacker = "None"
    hash = "d01144c04e7a46870a8dd823eb2fe5c8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "array('cpp','cxx','hxx','hpp','cc','jxx','c++','vcproj'),"
    $s9 = "++$F; $File = urlencode($dir[$dirFILE]); $eXT = '.:'; if (strpos($dir[$dirFILE],"
  condition:
    all of them
}