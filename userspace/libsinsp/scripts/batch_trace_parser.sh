DIRNAME=tace_parser_$(date +%F_%H-%M-%S)

mkdir $DIRNAME

for f in *.scap
do 
 echo "Processing $f"
 ./sdump -r $f > $DIRNAME/$f.txt
 RETVAL=$?
 [ $RETVAL -eq 0 ] && echo Success
 [ $RETVAL -ne 0 ] && echo Failure && rm -f $DIRNAME/$f.txt
done

echo
echo Done. Data saved in $DIRNAME.