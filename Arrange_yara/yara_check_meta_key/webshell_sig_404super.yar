rule webshell_sig_404super {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file 404super.php"
    family = "None"
    hacker = "None"
    hash = "7ed63176226f83d36dce47ce82507b28"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "$i = pack('c*', 0x70, 0x61, 99, 107);" fullword
    $s6 = "    'h' => $i('H*', '687474703a2f2f626c616b696e2e64756170702e636f6d2f7631')," fullword
    $s7 = "//http://require.duapp.com/session.php" fullword
    $s8 = "if(!isset($_SESSION['t'])){$_SESSION['t'] = $GLOBALS['f']($GLOBALS['h']);}" fullword
    $s12 = "//define('pass','123456');" fullword
    $s13 = "$GLOBALS['c']($GLOBALS['e'](null, $GLOBALS['s']('%s',$GLOBALS['p']('H*',$_SESSIO"
  condition:
    1 of them
}