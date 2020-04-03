rule webshell_c99_Shell_ci_Biz_was_here_c100_v_xxx {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell"
    family = "None"
    hacker = "None"
    hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
    hash1 = "f2fa878de03732fbf5c86d656467ff50"
    hash2 = "27786d1e0b1046a1a7f67ee41c64bf4c"
    hash3 = "0f5b9238d281bc6ac13406bb24ac2a5b"
    hash4 = "68c0629d08b1664f5bcce7d7f5f71d22"
    hash5 = "048ccc01b873b40d57ce25a4c56ea717"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s8 = "else {echo \"Running datapipe... ok! Connect to <b>\".getenv(\"SERVER_ADDR\""
  condition:
    all of them
}