from injections.XSS_Test import main as xss_check


class Injector:
    pass


def check_url_for_xss(url_with_get_parameters):
    return xss_check(url_with_get_parameters)


if __name__ == "__main__":
    what_we_got = check_url_for_xss(
        "https://xss-game.appspot.com/level1/frame?query=1")
    print(what_we_got)
