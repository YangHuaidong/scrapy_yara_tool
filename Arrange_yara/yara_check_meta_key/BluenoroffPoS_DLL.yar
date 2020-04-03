rule BluenoroffPoS_DLL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-06-07"
    description = "Bluenoroff POS malware - hkp.dll"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://blog.trex.re.kr/3?category=737685"
    threatname = "None"
    threattype = "None"
  strings:
    $dll = "ksnetadsl.dll" ascii wide fullword nocase
    $exe = "xplatform.exe" ascii wide fullword nocase
    $agent = "Nimo Software HTTP Retriever 1.0" ascii wide nocase
    $log_file = "c:\\windows\\temp\\log.tmp" ascii wide nocase
    $base_addr = "%d-BaseAddr:0x%x" ascii wide nocase
    $func_addr = "%d-FuncAddr:0x%x" ascii wide nocase
    $HF_S = "HF-S(%d)" ascii wide
    $HF_T = "HF-T(%d)" ascii wide
  condition:
    5 of them
}