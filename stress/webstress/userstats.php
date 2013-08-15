<html>
 <head>
  <title>Test PHP</title>
 </head>
 <body>
<?php
$username="root";
$password="hmrmamwd";
$database="zencart";
$query="select * from products";

echo "Hello World!<p>";
/*
for($counter = 0; $counter <= 10; $counter++) 
{
    error_log("hello\n",3,"/root/php.log"); 
}
*/
mysql_connect("127.0.0.1",$username,$password);

@mysql_select_db($database) or die( "Unable to select database");

$result=mysql_query($query) or die( "query failed");
$num=mysql_numrows($result);
echo "rows=" + $num + "<p>";

mysql_close();

?>
 </body>
</html>

