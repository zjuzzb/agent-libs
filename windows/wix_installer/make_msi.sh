if [ ! -f etc/dragent.yaml ]; then
    echo "" > etc/dragent.yaml
fi

/cygdrive/c/Program\ Files\ \(x86\)/WiX\ Toolset\ v3.11/bin/candle.exe dragent.wxs
/cygdrive/c/Program\ Files\ \(x86\)/WiX\ Toolset\ v3.11/bin/light.exe dragent.wixobj
