
from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def hello_world():
    return render_template("index.html")
    return "<p>Home Page</p>"

@app.route("/about")
def about():
    return render_template("about.html")
    return "<p>About Page</p>"

@app.route("/dashboard/<name>")
def dashboard(name):
    items = ["Item 1", "Item 2", "Item 3"]
    return render_template("dashboard.html", name=name, items=items)
    return "<p>Dashbord Page</p>"

@app.route("/contact")
def contact():
    return render_template("contact.html")
    return "<p>Contact Page</p>"

if __name__ == '__main__':
    app.run(debug=True)