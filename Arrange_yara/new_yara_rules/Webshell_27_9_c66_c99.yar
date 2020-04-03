rule Webshell_27_9_c66_c99 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-01-11"
    description = "Detects Webshell - rule generated from from files 27.9.txt, c66.php, c99-shadows-mod.php, c99.php ..."
    family = "None"
    hacker = "None"
    hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
    hash10 = "a4db77895228f02ea17ff48976e03100ddfaef7c9f48c1d40462872f103451d5"
    hash2 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
    hash3 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
    hash4 = "80ec7831ae888d5603ed28d81225ed8b256c831077bb8feb235e0a1a9b68b748"
    hash5 = "6ce99e07aa98ba6dc521c34cf16fbd89654d0ba59194878dffca857a4c34e57b"
    hash6 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
    hash7 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
    hash8 = "615e768522447558970c725909e064558f33d38e6402c63c92a1a8bc62b64966"
    hash9 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/nikicat/web-malware-collection"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "if (!empty($unset_surl)) {setcookie(\"c99sh_surl\"); $surl = \"\";}" fullword ascii
    $s6 = "@extract($_REQUEST[\"c99shcook\"]);" fullword ascii
    $s7 = "if (!function_exists(\"c99_buff_prepare\"))" fullword ascii
  condition:
    filesize < 685KB and 1 of them
}