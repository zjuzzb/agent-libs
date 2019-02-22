# This powershell script builds the agent code in windows using cygwin and creates a dragent.msi package
# TODO: Enhance this script to
# 1) build the windows-agent-builder docker container
#    > cd C:\cygwin64\code\agent
#    > docker build -t windows-agent-builder windows
# 2) provide a powershell prompt to examine the container

# Copy out source code from agent, sysdig and oss-falco repos into container's code directory using rsync
# We don't want to modify the user's source code repos in any way
Start-Process -Wait -RedirectStandardOut C:\cygwin64\code\logs\log.out -RedirectStandardError C:\cygwin64\code\logs\log.err rsync -ArgumentList @('--delete','-t','-r','--exclude=.git','--exclude=dependencies','--exclude=build','--exclude="cointerface/draiosproto"','--exclude="cointerface/sdc_internal"','/cygdrive/c/draios/agent/','/code/agent/')
Start-Process -Wait -RedirectStandardOut C:\cygwin64\code\logs\log.out -RedirectStandardError C:\cygwin64\code\logs\log.err rsync -ArgumentList @('--delete','-t','-r','--exclude=.git','--exclude=dependencies','--exclude=build','--exclude="driver/Makefile"','--exclude="driver/driver_config.h"','/cygdrive/c/draios/sysdig/','/code/sysdig/')
Start-Process -Wait -RedirectStandardOut C:\cygwin64\code\logs\log.out -RedirectStandardError C:\cygwin64\code\logs\log.err rsync -ArgumentList @('--delete','-t','-r','--exclude=.git','--exclude=dependencies','--exclude=build','--exclude="userspace/engine/lua/lyaml*"','/cygdrive/c/draios/oss-falco/','/code/oss-falco/')

# The bash script files that we run in cygwin need to have Unix/Linux style line ending (LF) instead of Windows style line ending (CRLF)
# Use the dos2unix utility to convert these files
Start-Process -Wait -RedirectStandardOut C:\cygwin64\code\logs\log.out -RedirectStandardError C:\cygwin64\code\logs\log.err dos2unix -ArgumentList @('C:\cygwin64\code\agent\bootstrap-agent')
Start-Process -Wait -RedirectStandardOut C:\cygwin64\code\logs\log.out -RedirectStandardError C:\cygwin64\code\logs\log.err dos2unix -ArgumentList @('C:\cygwin64\code\agent\windows\build_installer_docker.sh')
Start-Process -Wait -RedirectStandardOut C:\cygwin64\code\logs\log.out -RedirectStandardError C:\cygwin64\code\logs\log.err dos2unix -ArgumentList @('C:\cygwin64\code\agent\windows\wix_installer\make_msi.sh')
Start-Process -Wait -RedirectStandardOut C:\cygwin64\code\logs\log.out -RedirectStandardError C:\cygwin64\code\logs\log.err dos2unix -ArgumentList @('C:\cygwin64\code\oss-falco\scripts\build-lpeg.sh')

# Finally enter the windows agent directory and launch the script to build and install the windows agent
cd C:\cygwin64\code\agent\windows
Start-Process -Wait -RedirectStandardOut C:\cygwin64\code\logs\log.out -RedirectStandardError C:\cygwin64\code\logs\log.err bash -ArgumentList @('.\build_installer_docker.sh')