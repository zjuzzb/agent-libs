f = open("test.txt", "wb")
f.write("1234567890");
f.close()
f = open("test.txt", "r")
s = f.read()
print s
f.close()
