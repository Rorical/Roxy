<?
$token = "keyskeyskeyskeyskeyskeyskeyskeys";


#error_reporting(0);
function get_request_method()
{
    if ( ! empty($_POST)) return 'POST';
    else return 'GET';
}

class AES {
	public $key;
    function __construct($k)
    {
        $this->key = $k;
    }
    public function encrypt($text)
    {
        try {
            $iv = substr($this->key, 0, 16);
            $length = 16;
            $count = strlen($text);
            if($count % $length != 0){
        		$add = $length - ($count % $length);
        	}else{
        		$add = 0;
        	}
        	$text = $text . str_repeat("\x00",$add);
            $encrypted = openssl_encrypt($text, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv);
            
        } catch (Exception $e) {
            print $e;
            return false;
        }
        return ($encrypted);
    }
    public function decrypt($encrypted)
    {
        try {
            $ciphertext_dec = base64_decode($encrypted);
            $iv = substr($this->key, 0, 16);
            $decrypted = openssl_decrypt($ciphertext_dec, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING,$iv);
        } catch (Exception $e) {
            return false;
        }
        return rtrim($decrypted,"\x00");

    }
}

function http_get($url,$headers)
{
    $curl = curl_init(); // 启动一个CURL会话
    $headers = array_merge((array)$headers,array('Accept-Encoding: gzip'));
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_HEADER, true);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false); // 跳过证书检查
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);  // 从证书中检查SSL加密算法是否存在
    curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
	curl_setopt($curl, CURLOPT_ENCODING, 'gzip,deflate');
    $tmpInfo = curl_exec($curl);     
    $headerSize = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
	// 根据头大小去获取头信息内容
	$header = trim(substr($tmpInfo, 0, $headerSize));
	$body = substr($tmpInfo, $headerSize);
    //关闭URL请求
    curl_close($curl);
    return array($header,$body);   
}

function http_head($url,$headers)
{
    $curl = curl_init(); // 启动一个CURL会话
    $headers = array_merge((array)$headers,array('Accept-Encoding: gzip'));
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_HEADER, true);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false); // 跳过证书检查
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);  // 从证书中检查SSL加密算法是否存在
    curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
	curl_setopt($curl, CURLOPT_ENCODING, 'gzip,deflate');
	curl_setopt($curl, CURLOPT_NOBODY, true);
	curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'HEAD');
    $tmpInfo = curl_exec($curl);     
	$header = trim($tmpInfo);
    //关闭URL请求
    curl_close($curl);
    return $header;   
}

function http_options($url,$headers)
{
    $curl = curl_init(); // 启动一个CURL会话
    $headers = array_merge((array)$headers,array('Accept-Encoding: gzip'));
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_HEADER, true);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false); // 跳过证书检查
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);  // 从证书中检查SSL加密算法是否存在
    curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
	curl_setopt($curl, CURLOPT_ENCODING, 'gzip,deflate');
	curl_setopt($curl, CURLOPT_NOBODY, true);
	curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'OPTIONS');
    $tmpInfo = curl_exec($curl);     
	$header = trim($tmpInfo);
    //关闭URL请求
    curl_close($curl);
    return $header;   
}

function http_post($url,$headers,$post)
{
    $curl = curl_init(); // 启动一个CURL会话
    $headers = array_merge((array)$headers,array('Accept-Encoding: gzip'));
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_HEADER, true);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false); // 跳过证书检查
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);  // 从证书中检查SSL加密算法是否存在
    curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
	curl_setopt($curl, CURLOPT_POST, 1);
	curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "POST");
	
    curl_setopt($curl, CURLOPT_POSTFIELDS, $post);
    curl_setopt($curl, CURLOPT_ENCODING, 'gzip,deflate');
    $tmpInfo = curl_exec($curl);
    $headerSize = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
	// 根据头大小去获取头信息内容
	$header = trim(substr($tmpInfo, 0, $headerSize));
	$body = substr($tmpInfo, $headerSize);
    //关闭URL请求
    curl_close($curl);
    return array($header,$body);   
}

function http_put($url,$headers,$post)
{
    $curl = curl_init(); // 启动一个CURL会话
    $headers = array_merge((array)$headers,array('Accept-Encoding: gzip'));
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_HEADER, true);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false); // 跳过证书检查
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);  // 从证书中检查SSL加密算法是否存在
    curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
	curl_setopt($curl, CURLOPT_PUT, 1);
	curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "PUT");
	
    curl_setopt($curl, CURLOPT_POSTFIELDS, $post);
    
    curl_setopt($curl, CURLOPT_ENCODING, 'gzip,deflate');
    $tmpInfo = curl_exec($curl);
    $headerSize = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
	// 根据头大小去获取头信息内容
	$header = trim(substr($tmpInfo, 0, $headerSize));
	$body = substr($tmpInfo, $headerSize);
    //关闭URL请求
    curl_close($curl);
    return array($header,$body);
}
function is_utf8($str){
	$len = strlen($str);
	for($i = 0; $i < $len; $i++){
		$c = ord($str[$i]);
		if ($c > 128) {
			if (($c > 247)) return false;
			elseif ($c > 239) $bytes = 4;
			elseif ($c > 223) $bytes = 3;
			elseif ($c > 191) $bytes = 2;
			else return false;
			if (($i + $bytes) > $len) return false;
			while ($bytes > 1) {
				$i++;
				$b = ord($str[$i]);
				if ($b < 128 || $b > 191) return false;
				$bytes--;
			}
		}
	}
	return true;
}
?>
<?php
	if(get_request_method()=="POST"){
		
		$aes = new AES($token);
		$url = ($aes -> decrypt($_POST['url']));
		if(!is_utf8($url)){
			echo "Passwd check failed";
			return;
		}
		$method = $_POST['method'];
		$dic_headers = json_decode(($aes -> decrypt($_POST['headers'])),true);
		foreach($dic_headers as $key => $value){
			$headers[] = "{$key}: {$value}";
		}
		if($method=="GET"){
			list($headers,$body) = http_get($url,$headers);
		}else if($method=="POST"){
			$post = gzuncompress($aes -> decrypt($_POST['data']));
			list($headers,$body) = http_post($url,$headers,$post);
		}else if($method=="HEAD"){
			$headers = http_head($url,$headers);
			$body = "";
		}else if($method=="OPTIONS"){
			$headers = http_options($url,$headers);
			$body = "";
		}else if($method=="PUT"){
			$post = gzuncompress($aes -> decrypt($_POST['data']));
			list($headers,$body) = http_put($url,$headers,$post);
		}else{
			$headers = "HTTP/1.1 500 Internal Server Error";
			$body = "";
		}
		$dic_headers = explode("\r\n", trim($headers));
		
		$status =  trim(strstr($dic_headers[0],' '));
		if(strtoupper($status)=="100 CONTINUE"){
			$headers = implode("\r\n",array_slice($dic_headers,1));
			$dic_headers = explode("\r\n", trim($headers));
			$status =  trim(strstr($dic_headers[0],' '));
		}
		$headers = array();
		foreach(array_slice($dic_headers,1) as $key => $value){
			$sphead = explode(":", $value);
			if(strtoupper(trim($sphead[0]))=="SET-COOKIE"){
				$headers["Cookies"] .= trim(implode(":",array_slice($sphead,1))) . "$";
			}else{
				$headers[trim($sphead[0])] = trim(implode(":",array_slice($sphead,1)));
			}
		}
		$result = array(
    		"status" => $status,
    		"headers" => $headers,
    		"content" => base64_encode(gzdeflate($body))
		);
		echo gzdeflate($aes -> encrypt(json_encode($result)));
	}else{
	echo '<h1>Roxy</h1><blockquote><p>Developed by <a href="https://www.boxpaper.club/" target=_blank"">Boxpaper</a></p></blockquote>';
	 } ?>