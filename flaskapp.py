from flask import Flask, url_for, render_template
from nagstatus import get_nag_status
from werkzeug.contrib.cache import SimpleCache
import datetime, time
app = Flask(__name__)
cache = SimpleCache()

STATE_OK = 0
STATE_WARNING = 1
STATE_CRITICAL = 2
STATE_UNKNOWN = 3

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
    level = level.lower()
    if "ok" in level:
        cache_level = STATE_OK
    elif "warn" in level:
        cache_level = STATE_WARNING
    elif "crit" in level:
        cache_level = STATE_CRITICAL
    else:
        cache_level = STATE_UNKNOWN

    return render_template('api_tbody.html', nag_status=cached_nag_status(level=cache_level), parse_row=parse_row)

if __name__ == "__main__":
    app.run(debug=True, use_debugger=False)
