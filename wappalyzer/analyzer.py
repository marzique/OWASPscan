from .__init__ import Wappalyzer


def getSimple(url):
    wappalyzer = Wappalyzer(url)
    apps = wappalyzer.analyze()
    simple_result = {}

    for appName, app in apps.items():
        categories = app.props.cats
        for category_id in categories:
            category_name = wappalyzer.db['categories'][str(category_id)]['name'].lower().replace(' ', '-')
            if category_name not in simple_result:
                simple_result.update({category_name: []})
            simple_result[category_name].append(appName)
    del wappalyzer
    return simple_result


def getDetail(url):  # wappalyzer styled output
    wappalyzer = Wappalyzer(url)
    apps = wappalyzer.analyze()
    detail_result = {"url": url, "applications": []}

    for appName, app in apps.items():
        f = {
            'name': app.name,
            'confidence': str(app.confidenceTotal),
            'version': app.version,
            'icon': app.props.icon,
            'website': app.props.website,
            'categories': [{str(c): wappalyzer.db['categories'][str(c)]['name']} for c in app.props.cats]
        }
        detail_result['applications'].append(f)
    del wappalyzer
    return detail_result