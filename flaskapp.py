#!/bin/env python2.7

from flask import Flask, url_for, render_template
from nagstatus import get_nag_status
from werkzeug.contrib.cache import SimpleCache
import time, json
app = Flask(__name__)
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

def cached_nag_status(status_file = '/root/projects/dashboard/status.dat', level = STATE_CRITICAL):
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

@app.route("/")
def index():
    return show_view('index')

@app.route("/view/<view_name>")
def show_view(view_name):
    if view_name == 'index':
        return render_template('view_test.html', nag_status=cached_nag_status(), parse_row=parse_row)
    return 'not implemented'

@app.route("/api/tbody")
@app.route("/api/tbody/<level>")
def api_tbody(level = 'critical'):
    cache_level = parse_level(level)
    return render_template('api_tbody.html', nag_status=cached_nag_status(level=cache_level), parse_row=parse_row)

@app.route("/api/json")
@app.route("/api/json/<level>")
def api_json(level = 'critical', nag_status = None):
    if not nag_status:
        cache_level = parse_level(level)
        nag_status = cached_nag_status(level=cache_level)
    output_array = []
    for host in nag_status:
        for service in nag_status[host]:
            if service != 'HOST':
                output_array.append(parse_row(nag_status[host][service]))
    return json.dumps(output_array)

def apply_filter(rule_group, service):
    """Applies a recursive rule test against [service]"""
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
        if operator == '=':
            return service_data == try_float(value)
        #fill in the other comparison operators here
        elif operator == 'regex':
            return re.search(value, service_data)
        elif operator == 'regexchild':
            return apply_filter(child, re.search(value, service_data).groups())
        elif operator == 'child':
            pass
        return False
    return False

def filter_data(filter, nag_data = None, level = 'critical'):
    """Applies [filter] to [nag_data]"""
    if not nag_data:
        cache_level = parse_level(level)
        nag_data = cached_nag_status(level = cache_level)
    





    return nag_data

@app.route("/api/filter/<filter>")
@app.route("/api/filter/<filter>/<level>")
@app.route("/api/filter/<filter>/<format>/<level>")
def api_filter(filter, level = 'critical', format = 'json'):
    """filters data and formats/chooses level if requested"""
    filter = filter.lower()
    if filter in test_filter_names:
        nag_status = filter_data(filter, level)
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
    app.run(debug=True, use_debugger=True)
