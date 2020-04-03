rule Wordpress_Config_Webshell_Preprend {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-25"
    description = "Webshell that uses standard Wordpress wp-config.php file and appends the malicious code in front of it"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    score = 65
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = " * @package WordPress" fullword ascii
    $s1 = "define('DB_NAME'," ascii
    $s2 = "require_once(ABSPATH . 'wp-settings.php');" ascii
    $fp1 = "iThemes Security Config" ascii
  condition:
    uint32(0) == 0x68703f3c and filesize < 400KB and
    $x1 and
    all of ($s*) and
    not $x1 in (0..1000) and
    not 1 of ($fp*)
}