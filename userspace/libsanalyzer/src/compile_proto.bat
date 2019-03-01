..\..\..\draios_win32_deps\protobuf-2.5.0\vsprojects\Release\protoc.exe -I=. --cpp_out=. .\draios.proto
unix2dos.exe draios.pb.cc
unix2dos.exe draios.pb.h
