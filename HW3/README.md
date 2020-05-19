# Network Security HomeWork 3 Report
---
## Simple HTTPS Server
### 1. 建置環境與使用說明
* **Visual Code**
* **WSL(Ubuntu 16.04)**
* **C code**
* **Makefile Command**
```
// build
make

// using sudo run server
make run
```
---
### 2. 重要程式碼說明
server.c
1. **isRoot()**
```cpp=
return (getuid() != 0) ? 0:1;
```
* **使用getuid()函數確認使用者權限**
2. **SSL_CTX\* InitServerCTX(void)**
```cpp=   
method = TLSv1_2_server_method(); // create new server-method instance
ctx = SSL_CTX_new(method); // create new context from method
```
* **使用method為server**
3. **void LoadCertificates(SSL_CTX\* ctx, char\* certFile, char\* keyFile)**
```cpp=
if ( SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0 )
{
    ERR_print_errors_fp(stderr);
    abort();
}
if ( SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0 )
{
    ERR_print_errors_fp(stderr);
    abort();
}
```
* **將憑證與私鑰載入到server**
4. **SSL\* ssl_create_connection(int fd, SSL_CTX\* ctx)**
```cpp=
SSL_set_fd(c_ssl, fd);
SSL_set_verify_depth(c_ssl, 1);
```
* **設定對應的fd與驗證深度, 因為只有一個憑證所以深度為一**
5. **void handleHttps(int c_fd, SSL\* c_ssl)**
```cpp=
if(strncmp(buf, "GET / ", 6) == 0)
{
    ...
}
else if(strncmp(buf,"GET /view ", 10) == 0)
{
    ...
}
else if((strncmp(buf, "POST ", 5) == 0)) // file POST get file name
{
    ...
}
else if((strncmp(buf, "GET /Download/", 14) == 0)) // Real file copy and download
{
    ...
}
else // wrong GET url
{
    ...
}
```
* **處理從網頁接到的Request並回應相對應的要求給client, 像是/view 顯示目前server當下所有資料提供client選取複製資料, POST則處理尋找client要求資料名稱並產生超連結提供client下載, 下載資料傳遞部分交由 GET /Download/執行。**
* **更詳細的內容都在程式中的註解**
---
### 設計架構與功能說明
* **設計架構:**
    * **創建socket建立連線**
    * **建立SSL連線**
        * **載入SSL憑證與金鑰**
        * **建立SSL連線**
    * **接收Http Request**
        * **SSL接收資訊**
        * **解析資訊並回覆**
* **功能與說明**
    * **Message Communication**
    * **Remote File Copy**
    * **Remote Shell(僅顯示清單, 即ls -a指令)**
### 成果截圖
1. 安全連線
![](https://i.imgur.com/qVaOQhU.png)
2. 顯示清單
![](https://i.imgur.com/fCola8O.png)
3. copy file(ex. Makefile)
![](https://i.imgur.com/0nxB6DH.png)
![](https://i.imgur.com/gPHBig3.png)
4. wrong page
![](https://i.imgur.com/nX6XN9e.png)
---
### 困難與心得
* **起初建立SSL連線因為chrome會先送出3個有error的request使得連線無法順利建立, 必須略過那些錯誤繼續連線才可以接受連線, 但網頁的憑證還是不會過, 會顯示不安全連線; 但用相同方式在Firefox上就不會有問題且可以順利連線, 顯示安全連線**
* **目前還不知道要如何解決chrome憑證的問題**
* **HTTPS連線上是基於SSL/TLS上的溝通, 讓資訊經過加密以保護用戶端資料不被竊盜或看見。憑證的部分則是要瀏覽器去幫忙驗證與確認是否是可信任的網頁。**
* **檔案複製那邊因為超連結被點選會再進一次httpHandle且會修改掉Request內容, 所以要再多一個判斷下載的Request, 然後處理接收到的內容擷取檔案名稱進行複製, 實作上比較麻煩**
###### tags: `Network_Security` `網路安全`