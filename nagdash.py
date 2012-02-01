#!/bin/env python2.7

from flask import Flask, url_for, render_template, g, redirect, flash, request, session, abort
from nagstatus import get_nag_status
from werkzeug.contrib.cache import SimpleCache
from werkzeug.security import generate_password_hash, check_password_hash
from contextlib import closing
from functools import wraps
import time, json, re, sqlite3, os
app = Flask(__name__)
app.config.from_pyfile('nagdash.cfg')
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
            return func(*args, **kwargs)
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

def init_views():
    session['views'] = [ ]

def add_view(filter, title):
    session['views'].append({ 'api_url': url_for('api_filter', filter=filter), 'title': title })

def filter_names():
    return [item[:-5] for item in os.listdir(app.config['FILTERPATH']) if item.endswith('.json')]

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
            create_user(request.form['username'], request.form['password'])
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

@app.route("/test/makeuser")
@require_login
def test_makeuser():
    return render_template('create_user.html')

@app.route("/test/useradd", methods=['GET', 'POST'])
@require_login
def test_useradd():
    if 'username' in request.form:
        create_user(request.form['username'], request.form['password'])
    return redirect(url_for('login'))

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
            add_view('services', 'Service Status')
            add_view('load', 'Load Status')
        return render_template('view_base.html')
    return 'not implemented'

@app.route("/settings")
@require_login
def settings():
    return render_template('settings.html')

@app.route("/edit/filters")
@require_login
def list_filters(error=""):
    filter_list = filter_names()
    return render_template('list_filters.html', filter_list = filter_list, error = error)

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
@require_login
def edit_filter():
    service_fields = cached_service_fields()
    operators=['=', '!=', '>', '>=', '<', '<=', 'regex', 'regexchild', 'child']
    chain_rules=['null', 'AND', 'OR', 'AND NOT', 'OR NOT']
    try:
        filtername = request.form['filter']
        with open(os.path.join(app.config['FILTERPATH'], '%s.json' % filtername), 'r') as f:
            filter_data = json.load(f)
    except:
        return render_template('edit_filter.html',
                    title=None,
                    service_fields=service_fields,
                    operators=operators,
                    chain_rules=chain_rules)
    return render_template('edit_filter.html',
                title=filtername,
                data=filter_to_form(filter_data, service_fields, operators, chain_rules),
                service_fields=service_fields,
                operators=operators,
                chain_rules=chain_rules)

@app.route("/api/savefilter", methods=['GET', 'POST'])
@require_login
def save_filter():
    valid_title = re.compile('[a-zA-Z0-9]+$')
    filtername = None
    #field, operator, value, chain
    if 'title' in request.form:
        if valid_title.match(request.form['title']):
            filtername = request.form['title'].lower()
    if filtername is None:
        abort(400)
    data_set = {}
    for column in ['field', 'operator', 'value', 'chain']:
        data_set[column] = request.form.getlist(column)
    parsed_data = parse_filter(data_set)
    with open(os.path.join(app.config['FILTERPATH'], '%s.json' % filtername), 'w') as f:
        json.dump(parsed_data, f, indent=4)
    return redirect(url_for('list_filters', error="Saved filter %s" % filtername))

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
        try: # validates data structures
            operator = rule['operator']
            field = try_float(rule['field']) #lets us use numeric indicies for regexchild requests
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
    with open(os.path.join(app.config['FILTERPATH'], '%s.json' % filter)) as f:
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
def api_filter(filter, level = 'critical', format = 'json'):
    """filters data and formats/chooses level if requested"""
    filter = filter.lower()
    if filter in filter_names():
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
