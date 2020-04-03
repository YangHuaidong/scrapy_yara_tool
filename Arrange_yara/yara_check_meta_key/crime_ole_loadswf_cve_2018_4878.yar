rule crime_ole_loadswf_cve_2018_4878 {
  meta:
    actor = "Purported North Korean actors"
    affected_versions = "Adobe Flash 28.0.0.137 and earlier versions"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Detects CVE-2018-4878"
    family = "None"
    hacker = "None"
    judge = "black"
    mitigation0 = "Implement Protected View for Office documents"
    mitigation1 = "Disable Adobe Flash"
    reference = "hxxps://www[.]krcert[.]or[.kr/data/secNoticeView.do?bulletin_writing_sequence=26998"
    threatname = "None"
    threattype = "None"
    version = "1.1"
    vuln_impact = "Use-after-free"
    vuln_type = "Remote Code Execution"
    weaponization = "Embedded in Microsoft Office first payloads"
  strings:
    $header = "rdf:RDF" wide ascii
    $title = "Adobe Flex" wide ascii
    $pdb = "F:\\work\\flash\\obfuscation\\loadswf\\src" wide ascii
    $s0 = "URLRequest" wide ascii
    $s1 = "URLLoader" wide ascii
    $s2 = "loadswf" wide ascii
    $s3 = "myUrlReqest" wide ascii
  condition:
    filesize < 500KB and all of ($header*) and
    all of ($title*) and 3 of ($s*) or all of ($pdb*) and all of ($header*) and 1 of ($s*)
}