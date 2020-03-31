rule StealthWasp_s_Basic_PortScanner_v1_2 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Auto-generated rule on file StealthWasp's Basic PortScanner v1.2.exe
    family = PortScanner
    hacker = None
    hash = 7c0f2cab134534cd35964fe4c6a1ff00
    judge = unknown
    reference = None
    threatname = StealthWasp[s]/Basic.PortScanner.v1.2
    threattype = s
  strings:
    $s1 = "Basic PortScanner"
    $s6 = "Now scanning port:"
  condition:
    all of them
}