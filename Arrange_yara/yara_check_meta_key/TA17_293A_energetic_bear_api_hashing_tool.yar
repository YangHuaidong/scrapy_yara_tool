rule TA17_293A_energetic_bear_api_hashing_tool {
  meta:
    assoc_report = "DHS Report TA17-293A"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Energetic Bear API Hashing Tool"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
    version = "2"
  strings:
    $api_hash_func_v1 = { 8A 08 84 C9 74 ?? 80 C9 60 01 CB C1 E3 01 03 45 10 EB ED }
    $api_hash_func_v2 = { 8A 08 84 C9 74 ?? 80 C9 60 01 CB C1 E3 01 03 44 24 14 EB EC }
    $api_hash_func_x64 = { 8A 08 84 C9 74 ?? 80 C9 60 48 01 CB 48 C1 E3 01 48 03 45 20 EB EA }
    $http_push = "X-mode: push" nocase
    $http_pop = "X-mode: pop" nocase
  condition:
    $api_hash_func_v1 or $api_hash_func_v2 or $api_hash_func_x64 and (uint16(0) == 0x5a4d or $http_push or $http_pop)
}