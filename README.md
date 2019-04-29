# rsa_ext
支持私钥加密公钥解密的rsa实现

公钥解密部分参考：<https://github.com/farmerx/gorsa>



### 用法

```go
import "github.com/Icepo/rsa_ext"
```



### go mod

```go
require github.com/Icepo/rsa_ext v1.0.0
```



### 密钥对生成

```go
/*
	openssl genrsa -out pri.pem 2048
	openssl rsa -in pri.pem -pubout -out pub.pem
	openssl pkcs8 -topk8 -inform PEM -in pri.pem -outform PEM -nocrypt > pkcs8_pri.pem
*/
```



* 私钥支持`pkcs8`和`pkcs1`两种模式

* 使用base64的密钥形式记得去掉头尾



### 签名

* 签名默认SHA512
* 使用`SignWithHash`可以自定义签名算法
