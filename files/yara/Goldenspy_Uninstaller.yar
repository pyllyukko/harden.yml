

rule Goldenspy_Uninstaller
{
meta:
  author = "SpiderLabs"
  malware_family = "GoldenSpy"
 filetype =  "exe_dll"
    
strings:

    $str1 = "taskkill /IM svm.exe /IM svmm.exe /F" ascii    //Kill the running process
    $str2 = "\\svm.exe -stopProtect" ascii                                //Stop the service
    $str3 = "\\svmm.exe -u" ascii                                                    //Uninstall the malware
    $str4 = "\\VCProject\\dgs\\Release\\" ascii                        //Project path
    $str5 = "dGFza2tpbGwgL0lNIHN2bS5leGUgL0lNIHN2bW0uZXhlIC9GIA" ascii
    $str6 = "c3ZtLmV4ZSAtc3RvcFByb3RlY3Q" ascii
    $str7 = "XHN2bW0uZXhlIC11" ascii
    $str8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\svm" ascii
    $str9 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cVW5pbnN0YWxsXHN2bQ" ascii


condition:    

    (uint16(0) == 0x5A4D) and 4 of ($str*) 
    
}
