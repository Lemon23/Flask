from flask import render_template, Flask
app=Flask(__name__)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('page_not_found.html'),404

if __name__ == '__main__':
    app.run(debug=True)

