#!/bin/env python2.7

from flask import Flask, url_for, render_template, g, redirect, flash, request, session
from nagstatus import get_nag_status
from werkzeug.contrib.cache import SimpleCache
from werkzeug.security import generate_password_hash, check_password_hash
from contextlib import closing
from functools import wraps
import time, json, re, sqlite3
app = Flask(__name__)
app.config.from_pyfile('nagdash.cfg')
cache = SimpleCache()

STATE_OK = 0
STATE_WARNING = 1
STATE_CRITICAL = 2
STATE_UNKNOWN = 3

test_filter_names = ["problem", "load"]
test_output_names = ["tbody", "json"]

def try_float(num):
    try:
        return float(num)
    except:
        return num

def parse_row(service_dict):
    """Parses out important service data to a tuple"""
    state_val = service_dict['current_state']
    if state_val == STATE_OK:
        state_name = "OK"
        state_column = 'last_time_ok'
    elif state_val == STATE_WARNING:
        state_name = "WARNING"
        state_column = 'last_time_warning'
    elif state_val == STATE_CRITICAL:
        state_name = "CRITICAL"
        state_column = 'last_time_critical'
    else:
        state_name = "UNKNOWN"
        state_column = 'last_time_unknown'
    duration = time.time() - service_dict[state_column]
    return (service_dict['host_name'], service_dict['service_description'], state_name, str(duration), "%s/%s" % (service_dict['current_attempt'], service_dict['max_attempts']), service_dict['plugin_output'])

def cached_nag_status(status_file = app.config['STATUS_FILE'], level = STATE_CRITICAL):
    """Tries to get current nag status from cache, regenerates and updates cache on failure."""
    status = cache.get('nag-status-%s' % level)
    if status is None:
        status = get_nag_status(status_file, level)
        cache.set('nag-status-%s' % level, status, timeout=10)
    return status

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
        try:
            if session['username'] is not None:
                return func(*args, **kwargs)
        except:
            pass
        return redirect(url_for('login', next=request.url))
    return decorated_func

def check_credentials(username, password):
    user = query_db('select * from users where USER = ?', [username], one=True)
    if user is None:
        return False
    else:
        return check_password_hash(user['PASSWORD'], password)

def create_user(username, password):
    query_db("insert into users VALUES (?,?)", [username, generate_password_hash(password)])
    g.db.commit()

def connect_db():
    return sqlite3.connect(app.config['DATABASE'])

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
def login(next = "/"):
    error = None
    # Check if any users exist:
    userresult = query_db('select count(*) from users', one=True)
    if userresult is None or userresult['count(*)'] == 0:
        error="No users exist, please create one now."
        init_db()
        if request.method == 'POST':
            create_user(request.form['username'], request.form['password'])
    if request.method == 'POST':
        try:
            if check_credentials(request.form['username'], request.form['password']):
                session['username'] = request.form['username']
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

@app.route("/view/<view_name>")
@require_login
def show_view(view_name):
    if view_name == 'index':
        return render_template('view_base.html', parse_row=parse_row)
    return 'not implemented'

@app.route("/api/tbody")
@app.route("/api/tbody/<level>")
@require_login
def api_tbody(level = 'critical'):
    cache_level = parse_level(level)
    return render_template('api_tbody.html', nag_status=cached_nag_status(level=cache_level), parse_row=parse_row)

@app.route("/api/json")
@app.route("/api/json/<level>")
@require_login
def api_json(nag_status = None, level = 'critical'):
    if not nag_status:
        cache_level = parse_level(level)
        nag_status = cached_nag_status(level=cache_level)
    output_array = []
    for host in nag_status:
        for service in nag_status[host]:
            if service != 'HOST':
                output_array.append(parse_row(nag_status[host][service]))
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
        try:
            operator = rule['operator']
            field = rule['field']
            chain = rule['chain']
            child = rule['child']
            value = rule['value']
            service_data = service[field]
        except:
            return False
        if operator == 'child':
            newval = apply_filter(child, service)
        elif operator == 'regexchild':
            match = re.search(value, service_data)
            if match:
                newval = apply_filter(child, match.groups())
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
    #FIXMEFIXMEFIXME
    with open('filterset.json') as f:
        rule_group = json.load(f)
    #rule_group = load_filter(filter)
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
def api_filter(filter, level = 'critical', format = 'json'):
    """filters data and formats/chooses level if requested"""
    filter = filter.lower()
    if filter in test_filter_names: #FIXMEFIXMEFIXME
        nag_status = filter_data(filter, level = level)
        if format == 'json':
            return api_json(nag_status)
        elif format == 'tbody':
            return api_tbody(nag_status)
        else:
            return """syntax is:<br>
@app.route("/api/filter/<filter>")<br>
@app.route("/api/filter/<filter>/<level>")<br>
@app.route("/api/filter/<filter>/<format>/<level>")"""

if __name__ == "__main__":
    app.run()
