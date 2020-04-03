rule webshell_aZRaiLPhp_v1_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file aZRaiLPhp v1.0.php"
    family = "None"
    hacker = "None"
    hash = "26b2d3943395682e36da06ed493a3715"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s5 = "echo \" <font color='#0000FF'>CHMODU \".substr(base_convert(@fileperms($"
    $s7 = "echo \"<a href='./$this_file?op=efp&fname=$path/$file&dismi=$file&yol=$path'><fo"
  condition:
    all of them
}