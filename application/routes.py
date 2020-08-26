from flask import render_template, redirect, url_for, request
from application import app, db, bcrypt
from application.models import Users, Entries
from application.forms import RegistrationForm, LoginForm, EntriesForm
from flask_login import login_user, current_user, logout_user, login_required

@app.route('/')
@app.route('/home')
def home():
	return render_template('home.html', title='Home')

@app.route("/register", methods=['GET', 'POST'])
def register():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = RegistrationForm()
	if form.validate_on_submit():
		hashed_pw = bcrypt.generate_password_hash(form.password.data)
		user = Users(first_name=form.first_name.data, last_name=form.last_name.data, email=form.email.data, password=hashed_pw)
		db.session.add(user)
		db.session.commit()
		return redirect(url_for('home'))
	return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = LoginForm()
	if form.validate_on_submit():
		user = Users.query.filter_by(email=form.email.data).first()
		if user and bcrypt.check_password_hash(user.password, form.password.data):
			login_user(user, remember=form.remember.data)
			next_page = request.args.get('next')
			if next_page:
				return redirect(next_page)
			else:
				return redirect(url_for('home'))
	return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
	logout_user()
	return redirect(url_for('login'))

@app.route('/inventories', methods=['GET', 'POST'])
@login_required
def inventories():
	data = Entries.query.all()
	form = EntriesForm(obj=data)
	# Pretty sure this cleaning of data in unecessary, but couldn't recall the 
	# correct method to be able to use the request data as an iterable object
	cleandata = []
	for row in data:
		datasplit = str(row).split('\r\n')
		cleandata.append(datasplit)
	if form.validate_on_submit():
		if request.form['submit'] == 'Add Record':
			entry = Entries(parent=form.parent.data,item=form.item.data)
			db.session.add(entry)
		elif request.form['submit'] == 'Delete':
			id = request.form['id']
			entry = Entries.query.filter_by(id=id).first()
			db.session.delete(entry)
		else:
			Entries.query.filter_by(id=form.id.data).update({'parent':form.parent.data,'item':form.item.data})
		db.session.commit()
		return redirect(url_for('inventories'))
	return render_template('inventories.html', title='Inventory', data=cleandata, form=form)

@app.errorhandler(404)
def not_found(e):
	return render_template('404.html'), 404