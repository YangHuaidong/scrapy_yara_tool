rule MAL_HawkEye_Keylogger_Gen_Dec18 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-12-10"
    description = "Detects HawkEye Keylogger Reborn"
    family = "None"
    hacker = "None"
    hash1 = "b8693e015660d7bd791356b352789b43bf932793457d54beae351cf7a3de4dad"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/James_inthe_box/status/1072116224652324870"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "HawkEye Keylogger" fullword wide
    $s2 = "_ScreenshotLogger" fullword ascii
    $s3 = "_PasswordStealer" fullword ascii
  condition:
    2 of them
}