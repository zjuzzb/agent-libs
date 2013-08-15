<html>
 <head>
  <title>Test PHP</title>
 </head>
 <body>
<?php

echo "Hello Draios!<p>";

$data = "a";
for($j = 0; $j < 8000; $j++)
{
    $data .= 'a';
}

$addr = gethostbyname("localhost");

for($j = 0; $j < 10; $j++)
{
    $client = stream_socket_client("tcp://$addr:17647", $errno, $errorMessage);

    if ($client === false) {
        throw new UnexpectedValueException("Failed to connect: $errorMessage");
    }

    fwrite($client, $data);
    echo stream_get_contents($client);

    fclose($client);
}

?>
 </body>
</html>

