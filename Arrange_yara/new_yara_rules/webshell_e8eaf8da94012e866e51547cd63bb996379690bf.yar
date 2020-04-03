rule webshell_e8eaf8da94012e866e51547cd63bb996379690bf {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-09-10"
    description = "Detects a web shell"
    family = "None"
    hacker = "None"
    hash1 = "027544baa10259939780e97dc908bd43f0fb940510119fc4cce0883f3dd88275"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/bartblaze/PHP-backdoors"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "@exec('./bypass/ln -s /etc/passwd 1.php');" fullword ascii
    $x2 = "echo \"<iframe src=mysqldumper/index.php width=100% height=100% frameborder=0></iframe> \";" fullword ascii
    $x3 = "@exec('tar -xvf mysqldumper.tar.gz');" fullword ascii
  condition:
    ( uint16(0) == 0x213c and filesize < 100KB and 1 of ($x*) ) or ( 2 of them )
}