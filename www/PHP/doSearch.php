<HTML>
<HEAD>
<LINK REL=stylesheet HREF=http://<? echo $host.":".$port; ?>/style.css type="text/css">
</HEAD>
<BODY BGCOLOR=#FFFFFF>

<?php
    $fp = fsockopen ($host, $port);

if (!$fp) {
    echo "$errstr ($errno)<br>\n";
} else {
    $outStr = "";
    fputs ($fp, "GET /dumpData.html?language=php HTTP/1.0\r\n\r\n");
    while (!feof($fp)) {
	$out = fgets($fp,128);
	if($out == "\n")
	    $begin = 1;
	else if($begin == 1)
	    $outStr .= $out;
    }
    fclose ($fp);
    eval($outStr);
}

// echo count($$ntopHash);

echo "<center>\n<table border>\n";
echo "<tr><th BGCOLOR=white>Host</th><th BGCOLOR=white>Values</th></tr>\n";

$match1 = "^".$val_1;
$match2 = $val_1;
$match3 = $val_1."$";

//echo "$crit_1 - $oper_1 ->".$val_1."<-\n<br>";

while(list($key, $val) = each($$ntopHash)) {

//echo "eregi($val[$crit_1]) = ".eregi($match1, $val[$crit_1])."<br>\n";

    if((($oper_1 == "lt") && ($val[$crit_1] != "") && ($val[$crit_1] < $val_1)) 
       || (($oper_1 == "gt") && ($val[$crit_1] != "") && ($val[$crit_1] > $val_1))
       || (($oper_1 == "eq") && ($val[$crit_1] != "") && ($val[$crit_1] == $val_1))
       || (($oper_1 == "startsWith") && ($val[$crit_1] != "") && (eregi($match1, $val[$crit_1]))) 
       || (($oper_1 == "contains") && ($val[$crit_1] != "") && (eregi($match2, $val[$crit_1]))) 
       || (($oper_1 == "doesntContain") && ($val[$crit_1] != "") && (!eregi($match2, $val[$crit_1]))) 
       || (($oper_1 == "endsWith") && ($val[$crit_1] != "") && (eregi($match3, $val[$crit_1]))) 
       ) {

	$url = "http://$host:$port/".ereg_replace(":", "_", $key).".html";
	echo "<tr><th align=center BGCOLOR=white><A HREF=$url>$key</A></th>";
	echo "<td><table border>\n";
	while (list ($key_1, $val_1) = each ($val))
	    if($val_1 != "0") 
		echo "<tr><th align=left>$key_1</th><td align=right>$val_1</td></tr>";
	echo "</table></td></tr>\n";
    }
}

echo "</table>\n";

// echo "<pre>$outStr<pre>";
?>


</center>
</body>
</html>
