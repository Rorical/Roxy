<?
#error_reporting(0);
function get_request_method()
{
    if ( ! empty($_POST)) return 'POST';
    else return 'GET';
}

function http_get($url,$headers)
{
    $curl = curl_init(); // 启动一个CURL会话
    $headers = array_merge($headers,array('Accept-Encoding: gzip'));
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
    $headers = array_merge($headers,array('Accept-Encoding: gzip'));
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
    $headers = array_merge($headers,array('Accept-Encoding: gzip'));
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
    $headers = array_merge($headers,array('Accept-Encoding: gzip'));
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
    $headers = array_merge($headers,array('Accept-Encoding: gzip'));
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
?>
<?php
	if(get_request_method()=="POST"){
		$url = $_POST['url'];
		$method = $_POST['method'];
		$dic_headers = json_decode($_POST['headers'],true);
		foreach($dic_headers as $key => $value){
			$headers[] = "{$key}: {$value}";
		}
		if($method=="GET"){
			list($headers,$body) = http_get($url,$headers);
		}else if($method=="POST"){
			$post = base64_decode($_POST['data']);
			list($headers,$body) = http_post($url,$headers,$post);
		}else if($method=="HEAD"){
			$headers = http_head($url,$headers);
			$body = "";
		}else if($method=="OPTIONS"){
			$headers = http_options($url,$headers);
			$body = "";
		}else if($method=="PUT"){
			$post = base64_decode($_POST['data']);
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
		echo gzdeflate(base64_encode(json_encode($result)));
	}else{
	echo '<h1>Roxy</h1><blockquote><p>Developed by <a href="https://www.boxpaper.club/" target=_blank"">Boxpaper</a></p></blockquote>';
	 } ?>