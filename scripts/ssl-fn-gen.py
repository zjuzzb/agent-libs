#!/bin/env python3

##
# This is a helper script used to generate boilerplate code for Sysdig-R OpenSSL shim.
# It's meant to be used with `undefined reference` errors due to missing libssl / libcrypto
# linking.
# Example use: ./ssl-fn-gen.py 'int FIPS_mode_set(int ONOFF);'
#
# I collected the list of `undefined reference` and then I did:
# cat undefined-list.txt | while read i; do grep -h "\<$i\>.*;$" /usr/include/openssl/*.h ; done | tee ssl-decls.h
# and:
# cat ssl-decls.h | while read i; do ./ssl-fn-gen.py "$i"; done | tee ssl-defs.cpp
# Please note that this didn't work that easily, and required some fixes on the generated code.
##

from sys import argv

declaration=argv[1]

retval=''
token=''
name=''
param_str=''
param_names=[]

for i in range(len(declaration)):
    c = declaration[i]
    if c not in ' *&(),;':
        token += c
    else:
        if c == '(':
            name=token
            retval = declaration[:i-len(name)]
            param_str=declaration[i:]
        elif c in ',)':
            param_names.append(token)

        token=''

if param_str[-1] == ';':
    param_str = param_str[:-1]

out = """{retval}{name}{param_str}
{{
    static {retval}(*{name}_PTR){param_str};
    if ({name}_PTR == nullptr)
    {{
        load_symbol("{name}", {name}_PTR);
    }}
    return {name}_PTR({params});
}}
""".format(retval=retval, name=name, param_str=param_str, params=', '.join(param_names))

print(out)
