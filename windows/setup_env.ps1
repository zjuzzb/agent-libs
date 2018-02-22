Install-WindowsFeature Net-Framework-Core -source \\network\share\sxs
Invoke-WebRequest -Uri https://s3.amazonaws.com/download.draios.com/dependencies/wix311.exe -OutFile wix311.exe
& .\wix311.exe -q
Invoke-WebRequest -Uri https://cygwin.com/setup-x86_64.exe -OutFile setup-x86_64.exe
& .\setup-x86_64.exe --quiet-mode --site http://cygwin.mirror.constant.com --packages bash | Out-Null
& .\setup-x86_64.exe --quiet-mode --site http://cygwin.mirror.constant.com --packages core | Out-Null
& .\setup-x86_64.exe --quiet-mode --site http://cygwin.mirror.constant.com --packages gcc-g++ | Out-Null
& .\setup-x86_64.exe --quiet-mode --site http://cygwin.mirror.constant.com --packages git | Out-Null
& .\setup-x86_64.exe --quiet-mode --site http://cygwin.mirror.constant.com --packages wget | Out-Null
& .\setup-x86_64.exe --quiet-mode --site http://cygwin.mirror.constant.com --packages make | Out-Null
& .\setup-x86_64.exe --quiet-mode --site http://cygwin.mirror.constant.com --packages patch | Out-Null
& .\setup-x86_64.exe --quiet-mode --site http://cygwin.mirror.constant.com --packages zip | Out-Null
& .\setup-x86_64.exe --quiet-mode --site http://cygwin.mirror.constant.com --packages unzip | Out-Null
& .\setup-x86_64.exe --quiet-mode --site http://cygwin.mirror.constant.com --packages cmake | Out-Null
& .\setup-x86_64.exe --quiet-mode --site http://cygwin.mirror.constant.com --packages autoconf | Out-Null
& .\setup-x86_64.exe --quiet-mode --site http://cygwin.mirror.constant.com --packages automake | Out-Null
& .\setup-x86_64.exe --quiet-mode --site http://cygwin.mirror.constant.com --packages chere | Out-Null
& .\setup-x86_64.exe --quiet-mode --site http://cygwin.mirror.constant.com --packages libtool | Out-Null
C:\cygwin64\Cygwin.bat
