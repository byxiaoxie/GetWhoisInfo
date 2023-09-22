import os,re,sys,time
import whois

from datetime import datetime

domainRegex = r'(?:(?:[-\w]+\.)+[-\w]{2,})'
domainnameList = []
completedlist = []
RetryList = []

def print_log(str,type):
    if not str.strip():
        return
    if type == 0:
        str = str.replace("\r","").replace("\n","")
        now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(now + "：" + str)
        with open("whois.log","a", encoding='utf-8', errors='replace') as file:
            file.write(now + "：" + str + "\n")
    else:
        print(str)
        with open("whois.log","a", encoding='utf-8', errors='replace') as file:
            file.write(str + "\n")

def sevetofile():
    with open("retrylist.txt","a", encoding='utf-8', errors='replace') as file:
        for name in RetryList:
            file.write(name + "\n")
    with open("completedlist.txt","a", encoding='utf-8', errors='replace') as file:
        for name in completedlist:
            file.write(name + "\n")

def formatDatetime(DateStr):
    if isinstance(DateStr, str):
        try:
            dt_obj = datetime.strptime(DateStr, '%Y-%m-%d %H:%M:%S.%f')
        except ValueError:
            dt_obj = datetime.strptime(DateStr, '%Y-%m-%d %H:%M:%S')
    elif isinstance(DateStr, datetime):
        dt_obj = DateStr
    else:
        raise ValueError("Unsupported input type")

    return dt_obj.strftime('%Y-%m-%d %H:%M:%S')

def GetExpirationDate(ExpDate):
    if ExpDate:
        if isinstance(ExpDate, list):
            expiration_date = ExpDate[0]
        else:
            expiration_date = ExpDate
        return expiration_date
    else:
        return 'Date not available'

def GetFileAll(folder_path):
    namelist = []

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.txt'):
                DTName = root.replace(path + '\\', '').split('\\')
                if len(DTName) > 1:
                    DTName.reverse()
                DTNmaeToStr = '.'.join(DTName)
                Dname = file.replace('.txt', '') + '.' + DTNmaeToStr
                namelist.append(Dname)
    return namelist

def CheckWhois(listArray, mods):
    for domain in listArray:
        try:
            if re.fullmatch(domainRegex, domain):
                expText = "未知"
                winfo = whois.whois(domain)

                if mods == 0:
                    if winfo.text == 'Socket not responding: timed out':
                        RetryList.append(domain)
                        continue;
                    elif winfo.state == None and winfo['expiration_date'] == None:
                        completedlist.append(domain)
                        print_log(f"域名:{winfo.domain} 查询失败:未知", 0)
                        continue;
                elif mods == 1:
                    RetryList.pop(0)

                expirationDate = GetExpirationDate(winfo['expiration_date'])

                if expirationDate != 'Date not available':
                    targetTime = datetime.strptime(formatDatetime(expirationDate), '%Y-%m-%d %H:%M:%S')
                    currentTime = datetime.now()
                    if currentTime > targetTime:
                        expText = "已过期"
                    else:
                        expText = "未过期"
                
                completedlist.append(domain)
                print_log(f"域名:{winfo.domain} 到期时间:{GetExpirationDate(expirationDate)} 域名状态:{expText}", 0)
            else:
                print(f"{domain} 不是有效域名")
        except KeyError as e:
            if winfo.text == 'BLACKLISTED: You have exceeded the query limit for your network or IP address and have been blacklisted.\r\n':
                print_log(f"BLACKLISTED: 您已超过网络或IP地址的查询限制，已被列入黑名单", 0)
                sevetofile()
                sys.exit()
            elif winfo.text != '' and e.args[0] == 'expiration_date':
                completedlist .append(domain)
                print_log(f"域名:{domain} 查询失败:获取到期时间失败", 0)
            else:
                print(e)
        except Exception as e:
            if e.args[0] == 'No Data Found\r\n':
                completedlist .append(domain)
                print_log(f"域名:{domain} 查询失败:域名不存在或whius数据库中暂未收录", 0)
            else:
                print(f"域名:{domain} 查询失败:{e}")

if __name__ == '__main__':
    path = r''

    domainnameList = GetFileAll(path)

    with open('completedlist.txt', 'r') as file:
        completed_domains = {line.strip() for line in file}

    domainnameList = [domain for domain in domainnameList if domain not in completed_domains]

    print_log(f"域名总数:{len(domainnameList)}", 0)

    CheckWhois(domainnameList, 0)
    CheckWhois(RetryList, 1)
    sevetofile()