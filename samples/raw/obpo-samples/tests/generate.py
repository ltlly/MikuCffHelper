# Author: hluwa <hluwa888@gmail.com>
# HomePage: https://github.com/hluwa
# CreateTime: 2022/3/27
import asyncio
import os

from pyppeteer import launch

DIRNAME = os.path.dirname(__file__)
TEMPLATE = open(os.path.join(DIRNAME, "template.html")).read()


async def generate_png(html, png):
    browser = await launch()
    page = await browser.newPage()
    await page.goto("file://" + html)
    await page.screenshot({'path': png, 'fullPage': True})
    await browser.close()


if __name__ == "__main__":
    for dir in os.listdir(DIRNAME):
        dir = os.path.join(DIRNAME, dir)
        if not os.path.isdir(dir): continue

        files = [f for f in os.listdir(dir) if f.endswith(".c")]
        width = int(100 / len(files))
        body = ""
        for f in files:
            body += """\
<div style="width:{}%; float:left;">
<h1> {} </h1>
<pre><code class="cpp">
{}
</code></pre>
</div>""".format(width, f, open(os.path.join(dir, f)).read())
        with open(os.path.join(dir, "compare.html"), 'w') as htmlout:
            htmlout.write(TEMPLATE.replace("{BODY}", body))
        asyncio.get_event_loop().run_until_complete(
            generate_png(os.path.join(dir, "compare.html"), os.path.join(dir, "compare.png")))

        with open(os.path.join(dir, "README.md"), 'w') as mdout:
            mdout.write("![](compare.png)")
