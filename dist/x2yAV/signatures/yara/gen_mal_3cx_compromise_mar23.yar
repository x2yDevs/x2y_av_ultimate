import "pe"

rule APT_MAL_NK_3CX_Malicious_Samples_Mar23_1 {
    meta:
       description = "Detects malicious DLLs related to 3CX compromise"
       author = "X__Junior, Florian Roth (Nextron Systems)"
       reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
       date = "2023-03-29"
       modified = "2023-04-20"
       score = 85
    strings:
       $opa1 = { 4C 89 F1 4C 89 EA 41 B8 40 00 00 00 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 4C 89 F0 FF 15 ?? ?? ?? ?? 4C 8D 4C 24 ?? 45 8B 01 4C 89 F1 4C 89 EA FF 15 }
       $opa2 = { 48 C7 44 24 ?? 00 00 00 00 4C 8D 7C 24 ?? 48 89 F9 48 89 C2 41 89 E8 4D 89 F9 FF 15 ?? ?? ?? ?? 41 83 3F 00 0F 84 ?? ?? ?? ?? 0F B7 03 3D 4D 5A 00 00}
       $opa3 = { 41 80 7C 00 ?? FE 75 ?? 41 80 7C 00 ?? ED 75 ?? 41 80 7C 00 ?? FA 75 ?? 41 80 3C 00 CE}
       $opa4 = { 44 0F B6 CD 46 8A 8C 0C ?? ?? ?? ?? 45 30 0C 0E 48 FF C1}

       $opb1 = { 41 B8 40 00 00 00 49 8B D5 49 8B CC FF 15 ?? ?? ?? ?? 85 C0 74 ?? 41 FF D4 44 8B 45 ?? 4C 8D 4D ?? 49 8B D5 49 8B CC FF 15 }
       $opb2 = { 44 8B C3 48 89 44 24 ?? 48 8B 5C 24 ?? 4C 8D 4D ?? 48 8B CB 48 89 74 24 ?? 48 8B D0 4C 8B F8 FF 15 }
       $opb3 = { 80 78 ?? FE 75 ?? 80 78 ?? ED 75 ?? 80 38 FA 75 ?? 80 78 ?? CE }
       $opb4 = { 49 63 C1 44 0F B6 44 05 ?? 44 88 5C 05 ?? 44 88 02 0F B6 54 05 ?? 49 03 D0 0F B6 C2 0F B6 54 05 ?? 41 30 12}
    condition:
       uint16(0) == 0x5a4d
       and filesize < 5MB
       and pe.characteristics & pe.DLL
       and ( 2 of ($opa*) or 2 of ($opb*) )
}

rule APT_MAL_NK_3CX_Malicious_Samples_Mar23_2 {
    meta:
       description = "Detects malicious DLLs related to 3CX compromise (decrypted payload)"
       author = "Florian Roth (Nextron Systems)"
       date = "2023-03-29"
       score = 80
    strings:
       $s1 = "raw.githubusercontent.com/IconStorages/images/main/icon%d.ico" wide fullword
       $s2 = "https://raw.githubusercontent.com/IconStorages" wide fullword
       $s3 = "icon%d.ico" wide fullword
       $s4 = "__tutmc" ascii fullword

       $op1 = { 2d ee a1 00 00 c5 fa e6 f5 e9 40 fe ff ff 0f 1f 44 00 00 75 2e c5 fb 10 0d 46 a0 00 00 44 8b 05 7f a2 00 00 e8 0a 0e 00 00 }
       $op4 = { 4c 8d 5c 24 71 0f 57 c0 48 89 44 24 60 89 44 24 68 41 b9 15 cd 5b 07 0f 11 44 24 70 b8 b1 68 de 3a 41 ba a4 7b 93 02 }
       $op5 = { f7 f3 03 d5 69 ca e8 03 00 00 ff 15 c9 0a 02 00 48 8d 44 24 30 45 33 c0 4c 8d 4c 24 38 48 89 44 24 20 }
    condition:
       uint16(0) == 0x5a4d and
       filesize < 900KB and (3 of ($s*) or 2 of ($op*))
}

rule SUSP_APT_3CX_Regtrans_Anomaly_Apr23 {
    meta:
       description = "Detects suspicious .regtrans-ms files (Modified for X2yAV Compatibility)"
       author = "Florian Roth"
       score = 60
    strings:
       $fp1 = "REGISTRY" wide
       $mag = { EF BE AD DE }
    condition:
       $mag at 0 and filesize < 100KB and not 1 of ($fp*)
}

rule APT_MAL_VEILEDSIGNAL_Backdoor_Apr23_2 {
    meta:
       description = "Detects malicious VEILEDSIGNAL backdoor"
       author = "X__Junior"
       date = "2023-04-29"
       score = 80
    strings:
       $sa1 = "\\.\\pipe\\gecko.nativeMessaging" ascii
       $sa2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/95.0.1020.40" ascii
       $sa3 = "application/json, text/javascript, */*; q=0.01" ascii

       $op1 = { 89 7? 24 ?? 44 8B CD 4C 8B C? 48 89 44 24 ?? 33 D2 33 C9 FF 15}
       $op2 = { 4C 8B CB 4C 89 74 24 ?? 4C 8D 05 ?? ?? ?? ?? 44 89 74 24 ?? 33 D2 33 C9 FF 15}
       $op3 = { 48 89 74 24 ?? 45 33 C0 89 74 24 ?? 41 B9 ?? ?? ?? ?? 89 74 24 ?? 48 8B D8 48 C7 00 ?? ?? ?? ?? 48 8B 0F 41 8D 50 ?? 48 89 44 24 ?? 89 74 24 ?? FF 15}
    condition:
       uint16(0) == 0x5a4d and (all of ($op*) or all of ($sa*))
}

rule APT_MAL_NK_3CX_macOS_Elextron_App_Mar23_1 {
    meta:
       description = "Detects macOS malware used in the 3CX incident"
       author = "Florian Roth"
       date = "2023-03-31"
       score = 80
    strings:
       $a1 = "com.apple.security.cs.allow-unsigned-executable-memory" ascii
       $a2 = "com.electron.3cx-desktop-app" ascii fullword
       $s1 = "s8T/RXMlALbXfowom9qk15FgtdI=" ascii
       $s2 = "o8NQKPJE6voVZUIGtXihq7lp0cY=" ascii
    condition:
       (uint16(0) == 0xfacf or uint16(0) == 0xfeca) and
       filesize < 400KB and (all of ($a*) and 1 of ($s*))
}