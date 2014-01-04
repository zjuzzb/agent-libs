SINSOPEN=~/agent/build/debug/userspace/libsanalyzer/tests/01-open/sinsp-open
DIRNAME=trace_parser_$(date +%F_%H-%M-%S)
REFERENCEDIR=trace_parser_2014-01-03_20-49-02

mkdir $DIRNAME

for f in *.scap
do 
 echo "Processing $f"
# echo "$SINSOPEN -r $f -lstderr_nots -m $DIRNAME/metrics_$f > $DIRNAME/$f.output 2> $DIRNAME/$f.log"
 mkdir $DIRNAME/pb_$f
 valgrind --tool=memcheck --leak-check=yes --error-exitcode=33 --log-file=vg.txt $SINSOPEN -r $f -lstderr_nots -m $DIRNAME/pb_$f > $DIRNAME/$f.output 2> $DIRNAME/$f.log
 RETVAL=$?
 [ $RETVAL -ne 33 ] && echo no leaks && rm -f vg.txt
 [ $RETVAL -eq 33 ] && echo "MEMORY LEAK!!!" && cat vg.txt
done

echo
echo Data saved in $DIRNAME

echo
echo Comparing
diff -r --brief $DIRNAME $REFERENCEDIR
RETVAL=$?
[ $RETVAL -eq 0 ] && echo No change && rm -fr $DIRNAME
[ $RETVAL -ne 0 ] && echo Different!
