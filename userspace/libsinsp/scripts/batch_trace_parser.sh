SDUMP=/cygdrive/c/windump/GitHub/agent/userspace/Debug/sdump.exe
DIRNAME=tace_parser_$(date +%F_%H-%M-%S)
REFERENCEDIR=tace_parser_2013-12-23_17-45-41

mkdir $DIRNAME

for f in *.scap
do 
 echo "Processing $f"
# echo "$SDUMP -r $f -istderr_nots -m $DIRNAME/metrics_$f > $DIRNAME/$f.output 2> $DIRNAME/$f.log"
 mkdir $DIRNAME/pb_$f
 $SDUMP -r $f -istderr_nots -m $DIRNAME/pb_$f > $DIRNAME/$f.output 2> $DIRNAME/$f.log
 RETVAL=$?
 [ $RETVAL -eq 0 ] && echo Success
 [ $RETVAL -ne 0 ] && echo Failure && rm -f $DIRNAME/$f.output && rm -f $DIRNAME/$f.log
done

echo
echo Data saved in $DIRNAME

echo
echo Comparing
diff -r --brief $DIRNAME $REFERENCEDIR