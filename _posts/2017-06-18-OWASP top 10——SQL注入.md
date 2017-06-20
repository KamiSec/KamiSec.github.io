---
layout: post
title: "OWASP top 10——SQL注入"
date: 2017-06-18
description: "OWASP top 10"
tag: OWASP
---
## SQL注入攻击（SQL Injection）
简称注入攻击，是Web开发中最常见的一种安全漏洞。可以用它来从数据库获取敏感信息，或者利用数据库的特性执行添加用户，导出文件等一系列恶意操作，甚至有可能获取数据库乃至系统用户最高权限。
### 造成原因
因为程序没有有效的过滤用户的输入，使攻击者成功的向服务器提交恶意的SQL查询代码，程序在接收错误的将攻击者的输入作为查询语句的一部分执行，导致原始的查询逻辑被改变，额外的执行了攻击者精心构造的恶意代码。
### SQL注入实例
考虑一下简单的登录表单：
```
<form action=”/login” method=”POST”>
<p>Username:<input type=”text” name=”username” /></p>
<p>Password:<input type=“password” name=”password” /></p>
<p><input type=”submit” value=”登陆” /></p>
</from>
```
我们的处理里面的SQL可能是这样的：
```
username= r.Form.Get(“username”)
password= r.Form.Get(“password”)
sql= ”SELECT * FROM user WHERE username=’”+username+”’ AND password=’”+password+”’”
```
如果用户输入的用户名如下，密码任意
```
myuser’ or ‘foo’ = ‘foo’ --
```
那么我们的SQL变成了如下所示：
```
SELECT * FROM user WHERE username=’myuser’ or ‘foo’ = ‘foo’ --’ ’ AND password=’xxx’
```
在SQL里面 -- 是注释标记，所以查询语句会在此中断。这就让攻击者在不知道任何合法用户名和密码的情况下成功登录了。
对于SQL sever数据库还有更加危险的一种SQL注入，就是控制系统。
```
sql= “SELECT * FROM products WHERE name LIKE ‘%”+prod+”%’”
Db.Exec(sql)
```
如果攻击提交 a%’ exec master ..xp_cmdshell ‘net user test testpass /ADD’ -- 作为变量prod的值，那么sql将会变成：
```
sql= “SELECT * FROM products WHERE name LIKE ‘%a’ exec master ..xp_cmdshell ‘net user test testpass /ADD’--%’”
```
SQL sever 数据库会执行这条SQL语句，包括它后面那个用于向系统添加新用户的命令。如果这个程序是以sa运行而该服务有足够权限的话，攻击者就可以获得一个系统账号来访问主机了。
### 如何预防SQL注入
1.严格限制Web应用的数据库的操作权限，给此用户提供仅仅能够满足其工作的最低权限，从而最大限度的减少注入攻击对数据库的危害。
2.检查输入的数据是否具有所期望的数据格式，严格限制变量的类型，例如使用regexp包进行一些匹配处理，或者使用strconv包对字符串转化成其他基本类型的数据进行判断。
3.对进入数据库的特殊字符（'"\尖括号&*;等）进行转义处理，或编码转换。Go 的text/template 包里面的 HTMLEscapeString 函数可以对字符串进行转义处理。
4.所有的查询语句建议使用数据库提供的参数化查询接口，参数化的语句使用参数而不是将用户输入变量嵌入到SQL语句中，即不要直接拼接SQL语句。例如使用database/sql里面的查询函数Prepare和Query，或者 Exec(query string, args ...interface{})。
5.在应用发布之前建议使用专业的SQL注入检测工具进行检测，以及时修补被发现的SQL注入漏洞。网上有很多这方面的开源工具，例如 sqlmap、SQLninja 等。
6.避免网站打印出SQL错误信息，比如类型错误、字段不匹配等，把代码里的SQL语句暴露出来，以防止攻击者利用这些错误信息进行SQL注入。
### 手工注入：
1.判断注入点and 1=2
2.确定字段数order by
3.测试回显union select 1,2,3
4.爆表
5.爆字段
6.取数据

推荐网址：[SQL注入快速上手](http://www.jianshu.com/p/b562a0d03cbb)
## XXE
攻击者强制XML解析器去访问攻击者指定的资源内容（可能是系统上本地文件亦或是远程系统上的文件）。

推荐网址：[浅谈XXE攻击](http://www.freebuf.com/articles/web/126788.html)<br>
 		  [DTD/XXE 攻击笔记分享](http://www.freebuf.com/articles/web/97833.html)<br>
          [XXE漏洞攻防](https://security.tencent.com/index.php/blog/msg/69)
## Xpath注入
Xpath用于操作xml，我们通过搜索xpath来分析，提交给xpath函数的参数是否有经过安全处理。
### 攻击特点
XPath注入攻击利用两种技术，即XPath扫描和XPath查询布尔化。通过该攻击，攻击者可以控制用来进行XPath查询的XML数据库。这种攻击可以有效地对付使用XPath查询（和XML数据库）来执行身份验证、查找或者其他操作。XPath注入攻击同SQL注入攻击类似，但和SQL注入攻击相比较，XPath在以下方面具有广泛性和危害性大的优势。
### 攻击原理
XPath注入攻击主要是通过构建特殊的输入，这些输入往往是XPath语法中的一些组合，这些输入将作为参数传入Web应用程序，通过执行XPath查询而执行入侵者想要的操作，下面以登录验证中的模块为例。
在Web应用程序的登录验证程序中，一般有用户名（username）和密码（password）两个参数，程序会通过用户所提交的用户名和密码来执行授权操作。若验证数据存放在XML文件中，其原理是通过查找user表中的用户名（username）和密码（password）的结果来进行授权访问。
user.xml文件如下：
```
<users>
	<user>
		<firstname>Ben</firstname>
		<lastname>Elmore</lastname>
		<loginID>abc</loginID>
		<password>test123</password>
	</user>
	<user>
		<firstname>Shlomy</firstname>
		<lastname>Gantz</lastname>
		<loginID>xyz</loginID>
		<password>123test</password>
	</user>
</users>
```
则在XPath中典型的查询语句如下：
//users/user[loginID/text()=’xyz’ and password/text()=’123test’]
但是，可以采用如下的方法实施注入攻击，绕过身份验证。如果用户传入一个login和password,例如loginID=’xyz’和password=’123test’, 则该查询语句将返回 true。如果用户传入类似 ’or 1 = 1 or “=‘的值，那么该查询语句也会得到 true 返回值，因为XPath 查询语句最终会变成如下代码：
//users/user[loginID/text()=’’or 1=1 or “=’’ and password/text()=’’ or 1=1 or “ =’’]
这个字符串会在逻辑上使查询一直返回 true 并将一直允许攻击者访问系统。攻击者可以利用XPath在应用程序中动态地操作XML文档。攻击完成登录可以再通过XPath盲入技术获取最高权限账号和其他重要文档信息。
### XPath注入攻击防御技术
目前专门的XPath攻击防御技术还不是太多，但是SQL注入攻击防御技术可以加以改进，应用到XPath注入攻击防御。具体技术总结如下：
1.数据提交到服务器上端，在服务端正式处理这批数据之前，对提交数据的合法性进行验证。
2.检查提交的数据是否包含特殊字符，对特殊字符进行编码转换或替换、删除敏感字符或字符串。
3.对于系统出现的错误信息，以IE错误编码信息替换，屏蔽系统本身的出错信息。
4.参数化XPath查询，将需要构建的XPath查询表达式，以变量的形式表示，变量不是可以执行的脚本。如下代码可以通过创建保存查询的外部文件使查询参数化：
```
declare variable $loginID as xs : string external;
declare variable $password as xs : string external;
//users/user[@loginID=$loginID and@password= $password]
```
5.通过MD5、SSL等加密算法，对于数据敏感信息和在数据传输过程中加密，即使某些非法用户通过非法手段获取数据包，看到的也是加密后的信息。

推荐网址：[XPath Hacking技术科普](http://www.freebuf.com/articles/web/23184.html)
## OS命令注入
命令注入攻击（OS Command Injection）:系统提供命令执行类函数主要方便处理相关应用场景的功能。而当不合理的使用这类函数，同时调用的变量未考虑安全因素，就会执行恶意的命令调用，被攻击利用。
### 形成原因
此类命令执行函数依赖PHP配置文件的设置，如果配置选项safe_mode设置为off，此类命令不可执行，必须设置为On的情况下，才可执行。PHP默认是关闭的。在安全模式下，只有在特定目录中的外部程序才可以被执行，对其他程序的调用将被拒绝。这个目录可以在php.ini文件中用safe_mode_exec_dir指令，或在编译PHP是加上-with-exec-dir选项来制定，默认是/usr/local/php/bin。
### PHP执行函数
#### exec()函数
该函数可执行系统命令，并返回最后一条结果，然后使用foreach循环返回数组元素，得到命令结果。
command.php?cmd=ls -al
```
<?PHP
	echo exec($_GET[“cmd”],$res,$rc);
	foreach($res as $value)
	{
		echo $value;
	}
?>
```
#### system()函数
该函数执行命令，并返回所有结果。
system.php?cmd=ls -al
```
<?PHP
	system($_GET[“cmd”]);
?>
```
#### passthru()函数
passthru()只调用命令，不返回任何结果，但把命令的运行结果原样地直接输出到标准输出设备上。
system.php?cmd=ls -al
```
<?PHP
	passthru($_GET[“cmd”]);
?>
```
#### popen()函数
该函数可以执行系统命令，并可以与程序进行交互。
system.php?cmd=ls -al
```
<?PHP
	$hanle=popen($_GET[“cmd”],”r”);
	echo fread($hanle,2096);
	pclose($hanle);
?>
```
#### backtick operator
PHP支持一个执行运算符：反引号。PHP将尝试将反引号中的内容作为外壳命令来执行，并将其输出信息返回（例如，可以赋给一个变量而不是简单地丢弃到标准输出）。使用反引号运算符的效果与函数shell_exec()相同。
system.php?cmd=ls -al
```
<?PHP
	$res2 = $_GET[“cmd”];
	echo `$res2`;
?>
```
#### shell_exec()函数
该函数同样可以执行一个命令，并返回输出结果。
command.php?cmd=ls -al
```
<?PHP
	$output = shell_exec(‘ls -lart’);
	echo “$output”;
?>
```
### 防御方法
1.尽量避免使用此类函数。
2.因其危险性，执行命令的参数不要使用外部获取，防止用户构造。
3.设置PHP.ini配置文件中safe_mode = Off选项。默认为（off）；
4.使用自定义函数或函数库来代替外部命令的功能
5.使用escapeshellarg函数来处理命令参数
6.使用safe_mode_exec_dir指定可执行文件的路径
7.esacpeshellarg函数会将任何引起参数或命令结束的字符转义，单引号” ‘ “，替换成
” \’ “，双引号” “ ”，替换成” \” “，分号替换成” \; “。用safe_mode_exec_dir指定可执行文件的路径，可以把会使用的命令提前放入此路径内safe_mode = On safe_mode_exec_dir = /usr/local/php/bin
## LDAP注入
LDAP(Lightweight Directory Access Protocol)：轻量级目录访问协议，是一种在线目录访问协议，主要用于目录中资源的搜索和查询，是X.500的一种简便的实现。
利用LDAP注入技术的关键在于控制用于目录搜索服务的过滤器。使用这些技术，攻击者可能直接访问LDAP目录树下的数据库，及重要的公司信息。利用用户引入的参数生成LDAP查询。一个安全的Web应用在构造和将查询发送给服务器前应该净化用户传入的参数。在有漏洞的环境中，这些参数没有得到合适的过滤，因而攻击者可以注入任意恶意代码。
### AND注入
绕过访问控制
```
(&(USER=slisberger)(&)(PASSWORD=Pwd))
```
权限提升
```
document)(security_level=*))(&(directory=documents
```
### OR注入
信息泄露
```
(|(type=printer)(uid=*))(type=scanner)
```
### LDAP盲注入
假设攻击者可以从服务器相应中推测出什么，尽管应用没有报出错误信息，LDAP过滤器中注入的代码却生成了有效的响应或错误。攻击者可以利用这一行为向服务器问正确的或错误的问题。这种攻击称之为盲攻击。LDAP的盲注攻击比较慢但容易实施，因为它们基于二进制逻辑，能让攻击者从IDAP目录提取信息。
#### AND盲注入
假设一个Web应用想从一个LDAP目录列出所有可用的Epson打印机，错误信息不会返回，应用发送如下的过滤器：
```
(&(objectClass=printer)(type=Epson*))
```
使用这个查询，如果有可用的Epson打印机，其图标就会显示给客户端，否则没有图标出现。如果攻击者进行LDAP盲注入攻击
```
*)()objectClass=*))(&(objectClass=void
```
Web应用会构造如下查询：
```
(&(objectClass=*)(objectClass=*))(&(objectClass=void)(type=Epson*))
```
仅第一个LDAP过滤器会被处理：

```
(&(objectClass=*)(objectClass=*))
```
结果是，打印的图标一定会显示到客户端，因为这个查询总是会获得结果：过滤器objectClass=*总是返回一个对象。当图标被显示时相应为真，否则为假。
从这一点来看，使用盲注技术比较容易，例如构造如下的注入：
```
(&(objectClass=*)(objectClass=users))(&(objectClass=foo)(type=Epson*))
(&(objectClass=*)(objectClass=resources))(&(objectClass=foo)(type=Epson*))
```
这种代码注入的设置允许攻击者推测可能存在于LDAP目录服务中不同对象类的值。当响应Web页面至少包含一个打印机图标时，对象类的值就是存在的，另一方面而言，如果对象类的值不存在或没有对它的访问，就不会有图标出现。

#### OR盲注
这种情况下，用于推测想要的信息的逻辑与AND是相反的，因为使用的是OR逻辑操作符。OR环境的注入为：
```
(|objectClass=void)(objectClass=void))(&(objectClass=void)(type=Epson*))
```
这个LDAP查询没有从LDAP目录服务获得任何对象，打印机的图标也不会显示给客户端(FALSE)。如果在相应的Web页面中没有任何图标，则相应为TRUE。故攻击者可以注入下列LDAP过滤器来收集信息：
```
(|(objectClass=void)(objectClass=users))(&(objectClass=void)(type=Epson*))
(|(objectClass=void)(objectClass=resources))(&(objectClass=void)(type=Epson*))
```

推荐网址：[LDAP注入与防御剖析](http://static.hx99.net/static/drops/tips-967.html)
## 远程代码执行
远程代码执行漏洞，用户通过浏览器提交执行命令，由于服务器端没有针对执行函数做过滤，导致在没有绝对路径的情况下就执行命令，可能会允许攻击者通过改变$PATH或程序执行环境的其他方面来执行一个恶意构造代码。
### 漏洞原理
由于开发人员编写源码，没有针对代码中可执行的特殊函数入口做过滤，导致客户端可以提交恶意构造语句，并交由服务器端执行。命令注入攻击中WEB服务器没有过滤类似system(),eval(),exec()等函数是该漏洞攻击成功的主要原因。
### 漏洞实例
```
<?PHP
$log_string=$_GET[‘log’];
system(“echo\””.data(“Y-m-d H:i:s ”).” ”.$log_string.”\”>> /logs/”.$pre.”.”.data(“Y-m-d”).”.log”);}
?>
```
恶意用户只需要构造xxx.php?log=’id’形式的URL，即可通过浏览器在远程服务器上执行任意系统命令
### 解决方案
1.建议假定的所有输入都是可疑的，尝试对所有输入提交可能执行命令的构造语句进行严格的检查或者控制外部输入，系统命令执行函数的参数不允许外部传递。
2.不仅要验证数据的类型，还要验证其格式、长度、范围和内容。
3.不要仅仅在客户端做数据的验证与过滤，关键的过滤步骤在服务端进行。
4.对输出的数据也要检查，数据库里的值有可能会在一个大网站的多出都有输出，即使在输入做了编码等操作，在各处的输入点时也要进行安全检查。
5.在发布应用程序之前测试所有已知的威胁。
