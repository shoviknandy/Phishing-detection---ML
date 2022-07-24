import ipaddress
import pandas
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
import socket
import xgboost
import pickle

def diff_month(d1, d2):
    return (d1.year - d2.year) * 12 + d1.month - d2.month


def generate_data_set(url):
    try:
        data_set = []

        if not re.match(r"^https?", url):
            url = "http://" + url

        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
        except:
            response = ""
            soup = -999

        domain = re.findall(r"://([^/]+)/?", url)[0]
        if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")
        whois_response = whois.whois(domain)

        rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {
            "name": domain
        })

        try:
            global_rank = int(re.findall(
                r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
        except:
            global_rank = -1

        # 1.having_IP_Address
        try:
            ipaddress.ip_address(url)
            data_set.append(-1)
        except:
            data_set.append(1)

        # 2.URL_Length
        if len(url) < 54:
            data_set.append(1)
        elif len(url) >= 54 and len(url) <= 75:
            data_set.append(0)
        else:
            data_set.append(-1)

        # 3.Shortining_Service
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', url)
        if match:
            data_set.append(-1)
        else:
            data_set.append(1)

        # 4.having_At_Symbol
        if re.findall("@", url):
            data_set.append(-1)
        else:
            data_set.append(1)

        # 5.double_slash_redirecting
        list = [x.start(0) for x in re.finditer('//', url)]
        if list[len(list)-1] > 6:
            data_set.append(-1)
        else:
            data_set.append(1)

        # 6.Prefix_Suffix
        if re.findall(r"https?://[^\-]+-[^\-]+/", url):
            data_set.append(-1)
        else:
            data_set.append(1)

        # 7.having_Sub_Domain
        if len(re.findall("\.", url)) == 1:
            data_set.append(1)
        elif len(re.findall("\.", url)) == 2:
            data_set.append(0)
        else:
            data_set.append(-1)

        # 8.SSLfinal_State
        try:
            if response.text:
                data_set.append(1)
        except:
            data_set.append(-1)

        # 9.Domain_registeration_length
        expiration_date = whois_response.expiration_date
        registration_length = 0
        try:
            expiration_date = min(expiration_date)
            today = time.strftime('%Y-%m-%d')
            today = datetime.strptime(today, '%Y-%m-%d')
            registration_length = abs((expiration_date - today).days)

            if registration_length / 365 <= 1:
                data_set.append(-1)
            else:
                data_set.append(1)
        except:
            data_set.append(-1)

        # 10.Favicon
        if soup == -999:
            data_set.append(-1)
        else:
            try:
                for head in soup.find_all('head'):
                    for head.link in soup.find_all('link', href=True):
                        dots = [x.start(0)
                                for x in re.finditer('\.', head.link['href'])]
                        if url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                            data_set.append(1)
                            raise StopIteration
                        else:
                            data_set.append(-1)
                            raise StopIteration
            except StopIteration:
                #data_set.append(-1)
                pass


        # 11. HTTPS_token
        if re.findall(r"^https://", url):
            data_set.append(1)
        else:
            data_set.append(-1)



        # 12. URL_of_Anchor
        percentage = 0
        i = 0
        unsafe = 0
        if soup == -999:
            data_set.append(-1)
        else:
            for a in soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1

            try:
                percentage = unsafe / float(i) * 100



                if percentage < 31.0:
                    data_set.append(1)
                elif ((percentage >= 31.0) and (percentage < 67.0)):
                    data_set.append(0)
                else:
                    data_set.append(-1)
            except:
                data_set.append(1)


        # 13. Links_in_tags
        i = 0
        success = 0
        if soup == -999:
            data_set.append(-1)

        else:
            for link in soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                if url in link['href'] or domain in link['href'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for script in soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                if url in script['src'] or domain in script['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1
            try:
                percentage = success / float(i) * 100
            except:
                data_set.append(1)

            if percentage < 17.0:
                data_set.append(1)
            elif((percentage >= 17.0) and (percentage < 81.0)):
                data_set.append(0)
            else:
                data_set.append(-1)



        # 14. Submitting_to_email
        if response == "":
            data_set.append(-1)
        else:
            if re.findall(r"[mail\(\)|mailto:?]", response.text):
                data_set.append(-1)
            else:
                data_set.append(1)

        # 15. Abnormal_URL
        if response == "":
            data_set.append(-1)
        else:
            if response.text == whois_response:
                data_set.append(1)
            else:
                data_set.append(-1)

        # 16. Redirect
        if response == "":
            data_set.append(-1)
        else:
            if len(response.history) <= 1:
                data_set.append(-1)
            elif len(response.history) <= 4:
                data_set.append(0)
            else:
                data_set.append(1)

        # 17. on_mouseover
        if response == "":
            data_set.append(-1)
        else:
            if re.findall("<script>.+onmouseover.+</script>", response.text):
                data_set.append(1)
            else:
                data_set.append(-1)

        # 18. RightClick
        if response == "":
            data_set.append(-1)
        else:
            if re.findall(r"event.button ?== ?2", response.text):
                data_set.append(1)
            else:
                data_set.append(-1)

        # 19. popUpWidnow
        if response == "":
            data_set.append(-1)
        else:
            if re.findall(r"alert\(", response.text):
                data_set.append(1)
            else:
                data_set.append(-1)

        # 20. Iframe
        if response == "":
            data_set.append(-1)
        else:
            if re.findall(r"[<iframe>|<frameBorder>]", response.text):
                data_set.append(1)
            else:
                data_set.append(-1)

        # 21. age_of_domain
        if response == "":
            data_set.append(-1)
        else:
            try:
                registration_date = re.findall(
                        r'Registration Date:</div><div class="df-value">([^<]+)</div>', whois_response.text)[0]
                if diff_month(date.today(), date_parse(registration_date)) <= 6:
                    data_set.append(-1)
                else:
                    data_set.append(1)
            except:
                data_set.append(-1)

        # 22. DNSRecord
        dns = 1
        try:
            d = whois.whois(domain)
        except:
            dns = -1
        if dns == -1:
            data_set.append(-1)
        else:
            if registration_length / 365 <= 1:
                data_set.append(-1)
            else:
                data_set.append(1)

        # 23. web_traffic
        try:
            rank = BeautifulSoup(urllib.request.urlopen(
                "http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
            rank = int(rank)
            if (rank < 100000):
                data_set.append(1)
            else:
                data_set.append(0)
        except :
            data_set.append(-1)

        # 24. Page_Rank
        try:
            if global_rank > 0 and global_rank < 100000:
                data_set.append(1)
            else:
                data_set.append(-1)
        except:
            data_set.append(-1)

        # 25. Google_Index
        site = search(url, 5)
        if site:
            data_set.append(1)
        else:
            data_set.append(-1)
        #print("Entered")
        return data_set
    except:
        print("heavy traffic")
        return -1
def check(url):
    try:
        dataset=[]
        ret=generate_data_set(url)
        dataset.append(ret)
        print(dataset)
        feature_names = ['Containing IP', 'length of url', 'Using Shortining', 'IS @ Symbol', '// redirecting',
                         'Prefix AND Suffix', 'Sub Domain', 'SSL', 'Domain Lifespan', 'IS Favicon', 'HTTPS', 'Anchor',
                         'tags Containing Links', 'Submit email', 'Is Abnormal', 'Redirect', 'on mouseover', 'RightClick',
                         'popUpWidnow', 'Iframe', 'domain age', 'DNSRecord',
                         'web traffic', 'Page Rank', 'Google Index']

        validation = pandas.DataFrame(dataset,columns=feature_names)

        model = pickle.load(open('C:\\Users\\shovi\\phishing.pkl', 'rb'))
        ans=model.predict(validation)
        if ans==[1]:
            return (str(url)+"A Safe Website")
        else:
            return(str(url)+"\n"+" is a Phishing website")
    except:
        return "Can't reach the Website"




