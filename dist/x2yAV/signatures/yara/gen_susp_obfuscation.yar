rule SUSP_Base64_Encoded_Hex_Encoded_Code {
   meta:
      author = "Florian Roth (Nextron Systems)"
      description = "Detects hex encoded code that has been base64 encoded"
      date = "2019-04-29"
      score = 65
      reference = "https://www.nextron-systems.com/2019/04/29/spotlight-threat-hunting-yara-rule-example/"
      id = "2cfd278f-ff45-5e23-b552-dad688ab303b"
   strings:
      $x1 = { 78 34 4e ?? ?? 63 65 44 ?? ?? 58 48 67 }
      $x2 = { 63 45 44 ?? ?? 58 48 67 ?? ?? ?? 78 34 4e }

      $fp1 = "Microsoft Azure Code Signp$"
   condition:
      1 of ($x*) and not 1 of ($fp*)
}

rule SUSP_Double_Base64_Encoded_Executable {
   meta:
      description = "Detects an executable that has been encoded with base64 twice"
      author = "Florian Roth"
      reference = "https://twitter.com/TweeterCyber/status/1189073238803877889"
      score = 70
      date = "2019-10-29"
      modified = "2025-03-21"
   strings:
      $ = "VkdocGN5QndjbTluY21GdElHTmhibTV2ZENCaVpTQnlkVzRnYVc0Z1JFOVRJRzF2Wk" ascii wide
      $ = "ZHaHBjeUJ3Y205bmNtRnRJR05oYm01dmRDQmlaU0J5ZFc0Z2FXNGdSRTlUSUcxdlpH" ascii wide
      $ = "WR2hwY3lCd2NtOW5jbUZ0SUdOaGJtNXZkQ0JpWlNCeWRXNGdhVzRnUkU5VElHMXZaR" ascii wide
      $ = "Um9hWE1nY0hKdlozSmhiU0JqWVc1dWIzUWdZbVVnY25WdUlHbHVJRVJQVXlCdGIyUm" ascii wide
      $ = "JvYVhNZ2NISnZaM0poYlNCallXNXViM1FnWW1VZ2NuVnVJR2x1SUVSUFV5QnRiMlJs" ascii wide
      $ = "Sb2FYTWdjSEp2WjNKaGJTQmpZVzV1YjNRZ1ltVWdjblZ1SUdsdUlFUlBVeUJ0YjJSb" ascii wide
      $ = "VWFHbHpJSEJ5YjJkeVlXMGdZMkZ1Ym05MElHSmxJSEoxYmlCcGJpQkVUMU1nYlc5a1" ascii wide
      $ = "VhR2x6SUhCeWIyZHlZVzBnWTJGdWJtOTBJR0psSUhKMWJpQnBiaUJFVDFNZ2JXOWta" ascii wide
      $ = "VYUdseklIQnliMmR5WVcwZ1kyRnVibTkwSUdKbElISjFiaUJwYmlCRVQxTWdiVzlrW" ascii wide
      $ = "VkdocGN5QndjbTluY21GdElHMTFjM1FnWW1VZ2NuVnVJSFZ1WkdWeUlGZHBiak15" ascii wide
      $ = "ZHaHBjeUJ3Y205bmNtRnRJRzExYzNRZ1ltVWdjblZ1SUhWdVpHVnlJRmRwYmpNe" ascii wide
      $ = "WR2hwY3lCd2NtOW5jbUZ0SUcxMWMzUWdZbVVnY25WdUlIVnVaR1Z5SUZkcGJqTX" ascii wide
      $ = "Um9hWE1nY0hKdlozSmhiU0J0ZFhOMElHSmxJSEoxYmlCMWJtUmxjaUJYYVc0ek" ascii wide
      $ = "JvYVhNZ2NISnZaM0poYlNCdGRYTjBJR0psSUhKMWJpQjFibVJsY2lCWGFXNHpN" ascii wide
      $ = "Sb2FYTWdjSEp2WjNKaGJTQnRkWE4wSUdKbElISjFiaUIxYm1SbGNpQlhhVzR6T" ascii wide
      $ = "VWFHbHpJSEJ5YjJkeVlXMGdiWFZ6ZENCaVpTQnlkVzRnZFc1a1pYSWdWMmx1TX" ascii wide
      $ = "VhR2x6SUhCeWIyZHlZVzBnYlhWemRDQmlaU0J5ZFc0Z2RXNWtaWElnVjJsdU16" ascii wide
      $ = "VYUdseklIQnliMmR5WVcwZ2JYVnpkQ0JpWlNCeWRXNGdkVzVrWlhJZ1YybHVNe" ascii wide
   condition:
      1 of them
      /* Path checks disabled for X2yAV compatibility */
      // and not filepath contains "\\User Data\\Default\\Cache\\" 
      // and not filepath contains "\\cache2\\entries\\" 
      // and not filepath contains "\\Microsoft\\Windows\\INetCache\\IE\\" 
}

rule SUSP_Reversed_Base64_Encoded_EXE {
   meta:
      description = "Detects an base64 encoded executable with reversed characters"
      author = "Florian Roth (Nextron Systems)"
      date = "2020-04-06"
      score = 80
   strings:
      $s1 = "AEAAAAEQATpVT"
      $s2 = "AAAAAAAAAAoVT"
      $s3 = "AEAAAAEAAAqVT"
      $s4 = "AEAAAAIAAQpVT"
      $s5 = "AEAAAAMAAQqVT"

      $sh1 = "SZk9WbgM1TEBibpBib1JHIlJGI09mbuF2Yg0WYyd2byBHIzlGaU" ascii
      $sh2 = "LlR2btByUPREIulGIuVncgUmYgQ3bu5WYjBSbhJ3ZvJHcgMXaoR" ascii
      $sh3 = "uUGZv1GIT9ERg4Wag4WdyBSZiBCdv5mbhNGItFmcn9mcwBycphGV" ascii
   condition:
      filesize < 10000KB and 1 of them
}

rule SUSP_Script_Base64_Blocks_Jun20_1 {
   meta:
      description = "Detects suspicious file with base64 encoded payload in blocks"
      author = "Florian Roth (Nextron Systems)"
      date = "2020-06-05"
      score = 70
   strings:
      $sa1 = "<script language=" ascii
      $sb2 = { 41 41 41 22 2B 0D 0A 22 41 41 41 }
   condition:
      all of them
}

rule SUSP_Reversed_Hacktool_Author {
   meta:
      description = "Detects a suspicious reversed author string"
      author = "Florian Roth (Nextron Systems)"
      date = "2020-06-10"
      score = 65
   strings:
      $x1 = "iwiklitneg" fullword ascii wide
      $x2 = " eetbus@ " ascii wide
   condition:
      filesize < 4000KB and 1 of them
}

rule SUSP_Base64_Encoded_Hacktool_Dev {
   meta:
      description = "Detects a suspicious base64 encoded keyword"
      author = "Florian Roth (Nextron Systems)"
      date = "2020-06-10"
      score = 65
   strings:
      $ = "QGdlbnRpbGtpd2" ascii wide 
      $ = "BnZW50aWxraXdp" ascii wide 
      $ = "AZ2VudGlsa2l3a" ascii wide
      $ = "QGhhcm1qMH" ascii wide
      $ = "BoYXJtajB5" ascii wide
      $ = "AaGFybWowe" ascii wide
      $ = "IEBzdWJ0ZW" ascii wide
      $ = "BAc3VidGVl" ascii wide
      $ = "gQHN1YnRlZ" ascii wide
   condition:
      filesize < 6000KB and 1 of them
}