rule ShellCrew_StreamEx_1_msi_dll {
  meta:
    author = Spider
    comment = None
    date = 2017-02-10
    description = Auto-generated rule - file msi.dll.eng
    family = msi
    hacker = None
    hash1 = 883108119d2f4db066fa82e37aa49ecd2dbdacda67eb936b96720663ed6565ce
    hash2 = 5311f862d7c824d13eea8293422211e94fb406d95af0ae51358accd4835aaef8
    hash3 = 191cbeffa36657ab1ef3939da023cacbc9de0285bbe7775069c3d6e18b372c3f
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar
    threatname = ShellCrew[StreamEx]/1.msi.dll
    threattype = StreamEx
  strings:
    $s1 = "NDOGDUA" fullword ascii
    $s2 = "NsrdsrN" fullword ascii
  condition:
    ( uint16(0) == 0x4d9d and filesize < 300KB and all of them )
}