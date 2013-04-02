#!/usr/bin/env python

from flask import Flask, url_for, render_template, g, redirect, flash, request, session, abort
from nagstatus import get_nag_status
from werkzeug.contrib.cache import SimpleCache
from werkzeug.security import generate_password_hash, check_password_hash
from contextlib import closing
from functools import wraps
import time, json, re, sqlite3, os
app = Flask(__name__)
app.config.from_pyfile('instance/nagdash.cfg')
cache = SimpleCache()

STATE_OK = 0
STATE_WARNING = 1
STATE_CRITICAL = 2
STATE_UNKNOWN = 3

def try_float(num):
    try:
        return float(num)
    except:
        return num

def try_int(num):
    try:
        return int(num)
    except:
        return num

def humantime(timedelta):
    """Converts time durations to human readable time"""
    seconds = int(timedelta)
    years, seconds = divmod(seconds, (3600 * 24 * 365))
    days, seconds = divmod(seconds, (3600 * 24))
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if years > 0:
        return "%dy, %dd, %dh, %dm, %ds" % (years, days, hours, minutes,
                                            seconds)
    elif days > 0:
        return "%dd, %dh, %dm, %ds" % (days, hours, minutes, seconds)
    elif hours > 0:
        return "%dh, %dm, %ds" % (hours, minutes, seconds)
    elif minutes > 0:
        return "%dm, %ds" % (minutes, seconds)
    else:
        return "%ds" % seconds

def parse_row(service_dict, host_name = None, service_description = None):
    """Parses out important service data to a tuple"""
    state_val = service_dict['current_state']
    if state_val == STATE_OK:
        state_name = "OK"
    elif state_val == STATE_WARNING:
        state_name = "WARNING"
    elif state_val == STATE_CRITICAL:
        state_name = "CRITICAL"
    else:
        state_name = "UNKNOWN"
    if service_dict['problem_has_been_acknowledged'] == 1:
        state_name = "ACKNOWLEDGED"
    state_column = 'last_state_change'
    duration = time.time() - service_dict[state_column]
    if host_name is None:
        host_name = service_dict['host_name']
    if service_description is None:
        service_description = service_dict['service_description']
    host_column = host_name if 'NAG_BASE_URL' not in app.config else render_template('nag_link.html', host=host_name, linktype="host")
    service_column = service_description if 'NAG_BASE_URL' not in app.config else render_template('nag_link.html', host=host_name, service=service_description, linktype="service")
    flapping = "<img class='flapping' alt='Service is flapping' src='%s' />" % url_for('static', filename='sort.png') if service_dict['is_flapping'] == 1 else ""
    return (host_column,
            service_column,
            state_name,
            str(duration),
            humantime(duration),
            "%s/%s %s" % (service_dict['current_attempt'], service_dict['max_attempts'], flapping),
            service_dict['plugin_output'])

def cached_nag_status(status_file = app.config['STATUS_FILE'], level = STATE_CRITICAL):
    """Tries to get current nag status from cache, regenerates and updates cache on failure."""
    status = cache.get('nag-status-%s' % level)
    if status is None:
        status = get_nag_status(status_file, level)
        cache.set('nag-status-%s' % level, status, timeout=10)
    return status

def cached_service_fields():
    service_fields = cache.get('service-fields')
    if service_fields is None:
        host_data = cached_nag_status(level=STATE_OK).itervalues().next() # using OK here to ensure we get data, though it is slow
        service_list = host_data.keys()
        service_list = [item for item in service_list if item != 'HOST'] # must remove 'HOST'
        service_fields = sorted(host_data[service_list[0]].keys())
        for i in range(10):
            service_fields.append(str(i))
        cache.set('service-fields', service_fields, timeout=3600*24)
    return service_fields

def parse_level(level):
    """Converts text level to integer"""
    level = level.lower()
    if "ok" in level:
        cache_level = STATE_OK
    elif "warn" in level:
        cache_level = STATE_WARNING
    elif "crit" in level:
        cache_level = STATE_CRITICAL
    else:
        cache_level = STATE_UNKNOWN

    return cache_level

def require_login(func):
    """Decorates a function to require login"""
    @wraps(func)
    def decorated_func(*args, **kwargs):
        if 'username' in session:
            user = get_user(session['username'])
            if user and not user['DISABLED'] == 1:
                return func(*args, **kwargs)
        return redirect(url_for('login', next=request.url))
    return decorated_func

def require_admin(func):
    """Decorates a function to require admin privileges"""
    @wraps(func)
    def decorated_func(*args, **kwargs):
        if 'username' in session:
            user = get_user(session['username'])
            if user and user['ADMIN'] == 1 and not user['DISABLED'] == 1:
                return func(*args, **kwargs)
        return redirect(url_for('login', next=request.url))
    return decorated_func

def get_user(username):
    return query_db('select * from users where USER = ?', [username], one=True)

def check_credentials(username, password):
    user = get_user(username)
    if user is None:
        return False
    else:
        return check_password_hash(user['PASSWORD'], password)

def create_user(username, password, admin=0, disabled=0, viewlist=""):
    query_db("insert into users VALUES (?,?,?,?,?)", [username, generate_password_hash(password), admin, disabled, viewlist])
    g.db.commit()

def update_user(username, password=None, admin=None, disabled=None, viewlist=None):
    user = get_user(username)
    if user is None:
        return False
    if password is not None:
        user['PASSWORD'] = generate_password_hash(password)
    if admin is not None:
        user['ADMIN'] = admin
    if disabled is not None:
        user['DISABLED'] = disabled
    if viewlist is not None:
        user['VIEWLIST'] = ",".join(viewlist)
    query_db("update users set `PASSWORD` = ?, `ADMIN` = ?, `DISABLED` = ?, `VIEWLIST` = ? where USER = ?", [ user['PASSWORD'], user['ADMIN'], user['DISABLED'], user['VIEWLIST'], user['USER'] ])
    g.db.commit()
    return True

def list_users():
    return query_db('select * from users')

def get_view(viewname):
    return query_db('select * from views where NAME = ?', [viewname], one=True)

def get_description(viewname):
    view = get_view(viewname)
    if view is not None and 'DESCRIPTION' in view:
        return view['DESCRIPTION']
    else:
        return viewname

def create_view(viewname, description):
    query_db("insert into views VALUES (?,?)", [viewname, description])
    g.db.commit()

def update_view(viewname, description):
    view = get_view(viewname)
    if view is None:
        return False
    query_db("update views set `DESCRIPTION` = ? where `NAME` = ?", [description, viewname])
    g.db.commit()
    return True

def parse_viewlist(user):
    return user['VIEWLIST'].split(',')

def connect_db():
    return sqlite3.connect(os.path.join(app.instance_path, 'nagdash.db'))

def init_db():
    with closing(connect_db()) as db:
        with app.open_resource('nagdash.sql') as f:
            db.cursor().executescript(f.read())
        db.commit()

def query_db(query, args=(), one=False):
    try:
        cur = g.db.execute(query, args)
    except:
        return None
    rv = [dict((cur.description[idx][0], value)
               for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv

def init_views():
    view_list = parse_viewlist(get_user(session['username']))
    if len(view_list) > 0 and len(view_list[0]) > 0:
        session['views'] = parse_viewlist(get_user(session['username']))
    else:
        update_user(username=session['username'],
                    viewlist=app.config['DEFAULT_VIEWS'])
        session['views'] = app.config['DEFAULT_VIEWS']

    print session['views'], app.config['DEFAULT_VIEWS']

def filter_names():
    #leaving this here in case I want to offer admins the option to import new filters later
    #return [item[:-5] for item in os.listdir(os.path.join(app.instance_path, 'filters')) if item.endswith('.json') and not item.endswith('liveeditor.json')]
    return query_db('select * from views')

@app.before_request
def before_request():
    g.db = connect_db()

@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()

@app.route("/")
@require_login
def index():
    return show_view('index')

@app.route("/login", methods=['GET', 'POST'])
def login(next = None):
    error = None
    userresult = query_db('select count(*) from users', one=True)
    if userresult is None or userresult['count(*)'] == 0:
        error="No users exist, please create one now."
        init_db()
        if request.method == 'POST':
            create_user(request.form['username'], request.form['password'], admin=1, disabled=0)
    if request.method == 'POST':
        try:
            if check_credentials(request.form['username'], request.form['password']):
                session['username'] = request.form['username']
                if next is None:
                    next = url_for('index')
                return redirect(next)
            else:
                error="Invalid user name and/or password."
        except:
            error="Invalid data passed to login form."
    return render_template('login_form.html', error=error, next=next)

@app.route("/logout")
def logout():
    session['username'] = None
    return redirect(url_for('login'))

@app.route("/api/filterrow")
@require_login
def get_filter_row():
    service_fields=cached_service_fields()
    operators=['=', '!=', '>', '>=', '<', '<=', 'regex', 'regexchild', 'child']
    chain_rules=['null', 'AND', 'OR', 'AND NOT', 'OR NOT']
    return render_template("filter_element.html", service_fields=service_fields, operators=operators, chain_rules=chain_rules)

def parse_filter(raw_columns):
    filter = []
    while len(raw_columns['field']) > 0:
        row = {}
        for column in ['field', 'operator', 'chain', 'value']:
            row[column] = raw_columns[column].pop(0)
        row['child'] = None
        if 'child' in row['operator']:
            row['child'] = parse_filter(raw_columns)
        filter.append(row)
        if 'null' in row['chain']:
            return filter
    return filter

@app.route("/view/<view_name>")
@require_login
def show_view(view_name):
    if view_name == 'index':
        if 'views' not in session:
            init_views()
        return render_template('view_base.html', get_description = get_description)
    return 'not implemented'

@app.route("/settings")
@require_login
def settings():
    return render_template('settings.html')

@app.route("/edit/filters", methods=['GET', 'POST'])
@require_login
def list_filters(error=""):
    if 'submit' in request.form:
        session['views'] = [ i for i in request.form if i != 'submit' ]
        error = "Updated form listing."
    elif 'views[]' in request.form:
        update_user(session['username'], viewlist=request.form.getlist('views[]'))
        init_views()
        return 'success'
    filter_list = [ i for i in filter_names() if not i['NAME'].endswith('liveeditor') ]
    return render_template('list_filters.html', filter_list = filter_list, error = error)

@app.route("/edit/users", methods=['GET', 'POST'])
@require_admin
def edit_users(error=""):
    if 'submit' in request.form:
        user_names = request.form.getlist('username')
        user_admins = request.form.getlist('admin')
        user_disableds = request.form.getlist('disabled')
        #Use a list comprehension to make a list of dicts with the correct names for each column
        user_list = [ {'USER': user, 'ADMIN': 1 if admin == "Yes" else 0, 'DISABLED': 1 if disabled == "Yes" else 0 } for (user, admin, disabled) in zip(user_names, user_admins, user_disableds) ]
        for user in user_list:
            update_user(user['USER'], admin=user['ADMIN'], disabled=user['DISABLED'])
    else:
        user_list = list_users()
    return render_template('list_users.html', user_list = user_list, error = error)

@app.route("/edit/user/<username>", methods=['GET', 'POST'])
@require_login
def edit_user(username, error=""):
    validate_username = re.compile('[a-zA-Z0-9]+$')
    if not validate_username.match(username):
        return redirect(url_for('edit_users'))
    user = get_user(username)
    admin = get_user(session['username'])['ADMIN'] == 1
    #ensure the logged in user has the right to edit this user
    if 'submit' in request.form and (admin or session['username'] == username):
        if request.form['password1'] == request.form['password2']:
            if not update_user(username, password=request.form['password1']):
                #if we get False above, it's because the user doesn't exist, so we must be an admin
                create_user(username, request.form['password1'])
                error = "User created"
            else:
                error = "Password updated"
        else:
            error = "Passwords must match"
    if user is None and not admin:
        return redirect(url_for('edit_users'))
    elif user is None:
        user = { 'USER': username, 'PASSWORD': '', 'ADMIN': 0, 'DISABLED': 0 }
        if error == "":
            error = "Couldn't find user %s, you may create it now." % username
    
    return render_template('edit_user.html', user=user, error=error)

def filter_to_form(data, service_fields, operators, chain_rules):
    mydata = ""
    if data is None:
        return mydata
    for row in data:
        try:
            myfield = row['field']
            myop = row['operator']
            myvalue = row['value']
            myrule = row['chain']
        except:
            continue
        if 'child' in row and row['child'] is not None:
            childdata=filter_to_form(row['child'], service_fields, operators, chain_rules)
        else:
            childdata=None
        mydata += render_template('filter_element.html',
                        service_fields=service_fields,
                        operators=operators,
                        chain_rules=chain_rules,
                        myfield=myfield,
                        myop=myop,
                        myvalue=myvalue,
                        myrule=myrule,
                        childdata=childdata)
    return mydata

@app.route("/edit/filter", methods=['GET', 'POST'])
@app.route("/edit/filter/<filtername>")
@require_admin
def edit_filter(filtername = None):
    service_fields = cached_service_fields()
    operators = ['=', '!=', '>', '>=', '<', '<=', 'regex', 'regexchild', 'child']
    chain_rules = ['null', 'AND', 'OR', 'AND NOT', 'OR NOT']
    try:
        if filtername is None:
            filtername = request.form['filter']
        with app.open_instance_resource('filters/%s.json' % filtername) as f:
            filter_data = json.load(f)
    except:
        return render_template('edit_filter.html',
                    title = None,
                    service_fields = service_fields,
                    operators = operators,
                    chain_rules = chain_rules,
                    get_description = get_description)
    try:
        description = get_view(filtername)['DESCRIPTION']
    except:
        description = ""

    return render_template('edit_filter.html',
                title = filtername,
                description = description,
                data=filter_to_form(filter_data, service_fields, operators, chain_rules),
                service_fields = service_fields,
                operators = operators,
                chain_rules = chain_rules)

@app.route("/api/savefilter", methods = ['POST'])
@require_admin
def save_filter():
    valid_title = re.compile('[a-zA-Z0-9]+$')
    filtername = None
    #field, operator, value, chain
    try:
        if valid_title.match(request.form['title']):
            filtername = request.form['title'].lower()
        description = request.form['description']
        if not update_view(filtername, description):
            create_view(filtername, description)
    except:
        abort(400)
            
    if filtername is None:
        abort(400)
    data_set = {}
    for column in ['field', 'operator', 'value', 'chain']:
        data_set[column] = request.form.getlist(column)
    parsed_data = parse_filter(data_set)
    with app.open_instance_resource('filters/%s.json' % filtername, mode='w') as f:
        json.dump(parsed_data, f, indent=4)
    return redirect(url_for('list_filters', error="Saved filter %s" % filtername))

@app.route("/api/deletefilter/<title>")
@require_admin
def delete_filter(title):
    query_db('delete from views where NAME = ?', [title], one=True)
    g.db.commit()
    return redirect(url_for('list_filters', error="Deleted filter %s" % title))

@app.route("/api/json")
@app.route("/api/json/<level>")
@require_login
def api_json(nag_status = None, level = 'critical', allow_host = False):
    if nag_status is None:
        cache_level = parse_level(level)
        nag_status = cached_nag_status(level=cache_level)
    output_array = []
    for host in nag_status:
        for service in nag_status[host]:
            if service != 'HOST':
                output_array.append(parse_row(nag_status[host][service]))
            elif allow_host:
                output_array.append(parse_row(nag_status[host][service],
                                              host_name=host,
                                              service_description=service))
    return json.dumps(output_array)

def chain_data(last_value, operator, next_value):
    operator = operator.lower()
    if operator == "and":
        return last_value and next_value
    elif operator == "or":
        return last_value or next_value
    elif operator == "or not":
        return last_value or not next_value
    elif operator == "and not":
        return last_value and not next_value
    else:
        return False

def conditional_chain(retval, chain_rule, newval):
    if chain_rule is None:
        return newval
    else:
        return chain_data(retval, chain_rule, newval)

def apply_filter(rule_group, service):
    """Applies a recursive rule test against [service]"""
    retval = None
    chain_rule = None
    for rule in rule_group:
        try: # validates data structures
            operator = rule['operator']
            field = try_int(rule['field'])
            chain = rule['chain']
            child = rule['child']
            value = rule['value']
            service_data = try_float(service[field])
        except:
            return False
        if operator == 'child':
            newval = apply_filter(child, service)
        elif operator == 'regexchild':
            match = re.search(value, service_data)
            if match:
                for i, v in enumerate(match.groups()):
                    service[i] = v
                newval = apply_filter(child, service)
            else:
                newval = False
        elif operator == 'regex':
            newval = re.search(value, service_data)
        elif operator == '=':
            newval = service_data == try_float(value)
        elif operator == '!=':
            newval = service_data != try_float(value)
        elif operator == '>':
            newval = service_data > try_float(value)
        elif operator == '<':
            newval = service_data < try_float(value)
        elif operator == '>=':
            newval = service_data >= try_float(value)
        elif operator == '<=':
            newval = service_data <= try_float(value)
        else:
            newval = False
        retval = conditional_chain(retval, chain_rule, newval)
        chain_rule = chain
    return retval

def filter_data(filter, nag_data = None, level = 'critical'):
    """Applies [filter] to [nag_data]"""
    if not nag_data:
        cache_level = parse_level(level)
        nag_data = cached_nag_status(level = cache_level)
    with app.open_instance_resource('filters/%s.json' % filter) as f:
        rule_group = json.load(f)
    del_list = []
    for host in nag_data:
        for service in nag_data[host]:
            if service != 'HOST':
                if not apply_filter(rule_group, nag_data[host][service]):
                    del_list.append((host, service))
    for host, service in del_list:
        del nag_data[host][service]
    return nag_data

@app.route("/api/filter/<filter>")
@app.route("/api/filter/<filter>/<level>")
@app.route("/api/filter/<filter>/<format>/<level>")
@require_login
def api_filter(filter, level = 'warning', format = 'json', show_if_down = False):
    """filters data and formats/chooses level if requested"""
    filter = filter.lower()
    if not show_if_down:
        down_hosts = api_host(level='warning', format='raw')
    if filter in [ view['NAME'] for view in filter_names() ]:
        if format == 'json' and re.match('[a-z]+$', level):
            #Adding caching with 5 second timeout because requests tend to bunch together
            nag_status = cache.get('filtered-%s-%s' % (filter, level))
            if nag_status is None:
                nag_status = filter_data(filter, level = level)
                if not show_if_down:
                    for host in nag_status.keys():
                        if host in down_hosts:
                            del nag_status[host]
                cache.set('filtered-%s-%s' % (filter, level), nag_status,
                          timeout=5)
            return api_json(nag_status)
        else:
            return """Didn't match regex"""
    else:
        return """filter wasn't in names.  %s""" % filter_names()

@app.route("/api/host")
@app.route("/api/host/<level>")
@app.route("/api/host/<level>/<format>")
@require_login
def api_host(level = 'warning', format = 'json'):
    """Returns HOST statuses filtered by <level> in format <format>"""
    if re.match('[a-z]+$', level):
        nag_data = cache.get('host-%s' % (level))
        if nag_data is None:
            cache_level = parse_level(level)
            nag_data = cached_nag_status(level = cache_level)
            for host in nag_data.keys():
                for service in nag_data[host].keys():
                    if not host in nag_data:
                        continue
                    elif service != 'HOST':
                        del nag_data[host][service]
                        continue
                    elif nag_data[host][service]['current_state'] < cache_level:
                        del nag_data[host]
                        continue
                    # This is because nagios says HOST DOWN is 1 but all other
                    # criticals are 2.
                    elif nag_data[host][service]['current_state'] == 1:
                        nag_data[host][service]['current_state'] = 2
            cache.set('host-%s' % (level), nag_data, timeout=5)
        if format == "json":
            return api_json(nag_data, allow_host = True)
        elif format == "raw":
            return nag_data
    else:
        return """Didn't match regex"""

if __name__ == "__main__":
    if 'HOST' in app.config:
        app.run(host=app.config['HOST'], debug=True)
    else:
        app.run()
