rule WaterBug_wipbot_2013_core {
  meta:
    author = Spider
    comment = None
    date = 22.01.2015
    description = Symantec Waterbug Attack - Trojan.Wipbot core + core; garbage appended data (PDF Exploit leftovers) + wipbot dropper; fake AdobeRd32 Error
    family = core
    hacker = None
    judge = unknown
    reference = http://t.co/rF35OaAXrl
    threatname = WaterBug[wipbot]/2013.core
    threattype = wipbot
  strings:
    $mz = "MZ"
    $code1 = { 89 47 0c c7 47 10 90 c2 04 00 c7 47 14 90 c2 10 00 c7 47 18 90 90 60 68 89 4f 1c c7 47 20 90 90 90 b8 89 4f 24 c7 47 28 90 ff d0 61 c7 47 2c 90 c2 04 00 }
    $code2 = { 85 C0 75 25 8B 0B BF ?? ?? ?? ?? EB 17 69 D7 0D 66 19 00 8D BA 5F F3 6E 3C 89 FE C1 EE 10 89 F2 30 14 01 40 3B 43 04 72 E4}
    $code3 = {90 90 90 ?? B9 00 4D 5A 90 00 03 00 00 00 82 04} $code4 = { 55 89 e5 5d c3 55 89 e5 83 ec 18 8b 45 08 85 c0 }
  condition:
    $mz at 0 and (($code1 or $code2) or ($code3 and $code4))
}