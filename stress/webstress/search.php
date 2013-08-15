<html>
 <head>
  <title>cpu test</title>
 </head>
 <body>
<?php

echo "cpu<p>";

$val = 0;
for($counter = 0; $counter <= 400000; $counter++) 
{
    $val = $val + $counter;
    $val = $val * 10;
    $val = $val % 333;
}

echo $val;
echo "<br>";
?>
 </body>
</html>

