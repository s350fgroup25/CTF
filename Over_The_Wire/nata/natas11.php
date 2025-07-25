<?php
 
function xor_decrypt($in,$json_input) {
    $key = $json_input;
    $text = $in;
    $outText = '';
 
    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }
 
    return $outText;
}
 
# Here's how to find $key
 
$defaultdata = array("showpassword"=>"no", "bgcolor"=>"#ffffff");
echo "Cookie value: ";
$cookie_white = 'MGw7JCQ5OC04PT8jOSpqdmkgJ25nbCorKCEkIzlscm5oKC4qLSgubjY=';
print($cookie_white);
echo "\r\n";
 
$base64_decode = base64_decode($cookie_white);
echo "After base64_decode(): ";
print($base64_decode);
 
$key_ans = xor_decrypt($base64_decode,json_encode($defaultdata));
echo "\r\n";
print("This is the key: ");
print($key_ans);
echo "\n";


 
$defaultdata2 = array( "showpassword"=>"yes", "bgcolor"=>"#ffffff");
 
function xor_encrypt($in) {
    $key = 'KNHL';
    $text = $in;
    $outText = '';
 
    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }
 
    return $outText;
}
 print("This is the anw: ");
print(base64_encode(xor_encrypt(json_encode($defaultdata2))));
echo "\r\n";
 
?>
