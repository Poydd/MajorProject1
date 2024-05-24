from flask import Flask, render_template, redirect, request, flash, session

from database import User, add_to_db, open_db
from common import utils

app = Flask(__name__)
app.secret_key = 'thisissupersecretkeyfornoone'


def login_session(user):
    session['uid'] = user.id
    session['username'] = user.username
    session['email'] = user.email
    session['isauth'] = True


def logout_session():
    session.pop('uid')
    session.pop('username')
    session.pop('email')
    session.pop('isauth')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if len(email) == 0:
            flash("email cannot be empty", 'error')
            return redirect('/login')
        if len(password) == 0:
            flash("password cannot be empty", 'error')
            return redirect('/login')
        # Logic for login
        db = open_db()
        user = db.query(User).filter(User.email == email).first()
        if user is None:
            flash("User not found", 'error')
            return redirect('/login')
        if user.password != password:
            flash("Invalid password", 'error')
            return redirect('/login')
        login_session(user)
        flash("Login successful", 'success')
        db.close()
        return redirect('/dashboard')
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_session()
    flash("Logged out successfully", 'success')
    return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        cpassword = request.form.get('cpassword')
        print(username, email, password, cpassword)
        # Logic for registration
        if len(username) == 0 or len(email) == 0 or len(password) == 0 or len(cpassword) == 0:
            flash("All fields are required", 'danger')
            return redirect('/register')  # Reload the page
        user = User(username=username, email=email, password=password)
        try:
            add_to_db(user)
            flash("Registration successful", 'success')
        except Exception as e:
            flash("User already exists", 'danger')
            return redirect('/register')
    return render_template('register.html')


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    user_name = session.get('username')

    if request.method == 'POST':
        # Handle settings form submission
        if 'new_username' in request.form:
            new_username = request.form.get('new_username')
            print("New Username =>", new_username)
            db = open_db()
            user = db.query(User).filter(User.username == user_name).first()
            user.username = new_username
            db.commit()
            db.close()
        elif 'old_pwd' in request.form and 'new_pwd' in request.form and 'confirmation' in request.form:
            old_password = request.form.get('old_pwd')
            new_password = request.form.get('new_pwd')
            confirmation = request.form.get('confirmation')
            print("Old Password =>", old_password)
            print("New Password =>", new_password)
            print("Confirmation =>", confirmation)
            if new_password != confirmation:
                flash("New password and confirmation do not match", 'danger')
                return redirect('/settings')
            db = open_db()
            user = db.query(User).filter(User.username == user_name).first()
            if user.password != old_password:
                flash("Invalid old password", 'danger')
                return redirect('/settings')
            user.password = new_password
            db.commit()
            db.close()
    return render_template('settings.html', user_name=user_name)


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    df = utils.load_data("analysis/netflix_titles_nov_2019.csv")
    fig1 = utils.plot_group_chart(df)
    fig2 = utils.years_end_chart(df)
    fig3 = utils.content_added_chart(df)
    fig4 = utils.season_count_chart(df)
    fig5 = utils.rating_chart(df)
    return render_template('dashboard.html',
                           figure1=fig1.to_html(),
                           figure2=fig2.to_html(),
                           figure3=fig3.to_html(),
                           figure4=fig4.to_html(),
                           figure5=fig5.to_html(),
                           )


@app.route('/dashboard/2', methods=['GET', 'POST'])
def dashboard2():
    df = utils.load_data("analysis/netflix_titles_nov_2019.csv")
    fig6 = utils.country_trace_chart(df)
    fig7 = utils.indian_director_chart(df)
    fig8 = utils.counts_of_movies_categories(df)
    return render_template('dashboard2.html', figure6=fig6.to_html(), figure7=fig7.to_html())


@app.route('/dashboard/3', methods=['GET', 'POST'])
def dashboard3():
    df = utils.load_data("analysis/netflix_titles_nov_2019.csv")

    fig8 = utils.counts_of_movies_categories(df)
    fig9 = utils.director_value_count(df)
    fig10 = utils.counts_of_the_rating(df)

    return render_template('dashboard3.html' ,figure8=fig8.to_html(), figure9=fig9.to_html(),
                           figure10=fig10.to_html())


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=True)
