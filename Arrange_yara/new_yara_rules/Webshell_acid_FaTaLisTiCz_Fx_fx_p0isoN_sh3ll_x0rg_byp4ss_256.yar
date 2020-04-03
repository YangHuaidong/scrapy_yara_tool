rule Webshell_acid_FaTaLisTiCz_Fx_fx_p0isoN_sh3ll_x0rg_byp4ss_256 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-01-11"
    description = "Detects Webshell"
    family = "None"
    hacker = "None"
    hash1 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
    hash2 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
    hash3 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
    hash4 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
    hash5 = "1fdf6e142135a34ae1caf1d84adf5e273b253ca46c409b2530ca06d65a55ecbd"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/nikicat/web-malware-collection"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<form method=\"POST\"><input type=hidden name=act value=\"ls\">" fullword ascii
    $s2 = "foreach($quicklaunch2 as $item) {" fullword ascii
  condition:
    filesize < 882KB and all of them
}