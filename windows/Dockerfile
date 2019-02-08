# escape=`

# start with windowsservercore as base os for the container
FROM microsoft/windowsservercore

# use powershell
SHELL ["powershell", "-command", "$ErrorActionPreference = 'Stop';"]

# install Windows Installer XML toolset
RUN mkdir C:\sxs ; `
	Invoke-WebRequest -Uri https://s3.amazonaws.com/download.draios.com/dependencies/microsoft-windows-netfx3-ondemand-package.cab -OutFile C:\sxs\microsoft-windows-netfx3-ondemand-package.cab ; `
	Install-WindowsFeature Net-Framework-Core -Source C:\sxs ; `
	Invoke-WebRequest -Uri https://s3.amazonaws.com/download.draios.com/dependencies/wix311.exe -OutFile wix311.exe ; `
	Start-Process .\wix311.exe -Wait -ArgumentList @('-q') ;

# install cygwin and all related packages that we need
RUN mkdir C:\cygwin64 ; cd C:\cygwin64 ; `
	Invoke-WebRequest -Uri https://cygwin.com/setup-x86_64.exe -OutFile setup-x86_64.exe ; `
	Start-Process .\setup-x86_64.exe -Wait -NoNewWindow -PassThru -ArgumentList @('-q','-s','http://cygwin.mirror.constant.com','-P','bash') ; `
	Start-Process .\setup-x86_64.exe -Wait -NoNewWindow -PassThru -ArgumentList @('-q','-s','http://cygwin.mirror.constant.com','-P','core') ; `
	Start-Process .\setup-x86_64.exe -Wait -NoNewWindow -PassThru -ArgumentList @('-q','-s','http://cygwin.mirror.constant.com','-P','gcc-g++') ; `
	Start-Process .\setup-x86_64.exe -Wait -NoNewWindow -PassThru -ArgumentList @('-q','-s','http://cygwin.mirror.constant.com','-P','git') ; `
	Start-Process .\setup-x86_64.exe -Wait -NoNewWindow -PassThru -ArgumentList @('-q','-s','http://cygwin.mirror.constant.com','-P','wget') ; `
	Start-Process .\setup-x86_64.exe -Wait -NoNewWindow -PassThru -ArgumentList @('-q','-s','http://cygwin.mirror.constant.com','-P','make') ; `
	Start-Process .\setup-x86_64.exe -Wait -NoNewWindow -PassThru -ArgumentList @('-q','-s','http://cygwin.mirror.constant.com','-P','patch') ; `
	Start-Process .\setup-x86_64.exe -Wait -NoNewWindow -PassThru -ArgumentList @('-q','-s','http://cygwin.mirror.constant.com','-P','zip') ; `
	Start-Process .\setup-x86_64.exe -Wait -NoNewWindow -PassThru -ArgumentList @('-q','-s','http://cygwin.mirror.constant.com','-P','unzip') ; `
	Start-Process .\setup-x86_64.exe -Wait -NoNewWindow -PassThru -ArgumentList @('-q','-s','http://cygwin.mirror.constant.com','-P','cmake') ; `
	Start-Process .\setup-x86_64.exe -Wait -NoNewWindow -PassThru -ArgumentList @('-q','-s','http://cygwin.mirror.constant.com','-P','autoconf') ; `
	Start-Process .\setup-x86_64.exe -Wait -NoNewWindow -PassThru -ArgumentList @('-q','-s','http://cygwin.mirror.constant.com','-P','automake') ; `
	Start-Process .\setup-x86_64.exe -Wait -NoNewWindow -PassThru -ArgumentList @('-q','-s','http://cygwin.mirror.constant.com','-P','chere') ; `
	Start-Process .\setup-x86_64.exe -Wait -NoNewWindow -PassThru -ArgumentList @('-q','-s','http://cygwin.mirror.constant.com','-P','libtool'); `
	Start-Process .\setup-x86_64.exe -Wait -NoNewWindow -PassThru -ArgumentList @('-q','-s','http://cygwin.mirror.constant.com','-P','dos2unix');

# install go
RUN cd C:\ ; $url = ('https://golang.org/dl/go1.11.4.windows-amd64.zip'); `
	Invoke-WebRequest -Uri $url -OutFile 'go.zip'; `
	Expand-Archive go.zip -DestinationPath C:\;

# create code dir and add cygwin and go to powershell path
RUN mkdir C:\cygwin64\code ; `
	mkdir C:\cygwin64\code\logs ; `
	setx path '%path%;C:\cygwin64\bin;C:\go\bin'

# copy entrypoint script
COPY docker-entrypoint.ps1 C:\cygwin64\code

# designate entry point
ENTRYPOINT C:\cygwin64\code\docker-entrypoint.ps1

