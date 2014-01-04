SINSOPEN=/cygdrive/c/windump/GitHub/agent/userspace/Debug/01-open.exe
DIRNAME=tace_parser_$(date +%F_%H-%M-%S)
#REFERENCEDIR=tace_parser_2013-12-23_17-45-41
REFERENCEDIR=tace_parser_2014-01-03_16-59-25
#REFERENCEDIR=good_noprotobuf

mkdir $DIRNAME

for f in *.scap
do 
 echo "Processing $f"
# echo "$SINSOPEN -r $f -istderr_nots -m $DIRNAME/metrics_$f > $DIRNAME/$f.output 2> $DIRNAME/$f.log"
 mkdir $DIRNAME/pb_$f
 $SINSOPEN -r $f -lstderr_nots -m $DIRNAME/pb_$f > $DIRNAME/$f.output 2> $DIRNAME/$f.log
 RETVAL=$?
 [ $RETVAL -eq 0 ] && echo Success
 [ $RETVAL -ne 0 ] && echo Failure && rm -f $DIRNAME/$f.output && rm -f $DIRNAME/$f.log
done

echo
echo Data saved in $DIRNAME

echo
echo Comparing
diff -r --brief $DIRNAME $REFERENCEDIR