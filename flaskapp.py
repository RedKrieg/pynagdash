from flask import Flask, url_for, render_template
from nagstatus import get_nag_status
from werkzeug.contrib.cache import SimpleCache
import datetime, time
app = Flask(__name__)
cache = SimpleCache()

def parse_row(service_dict):
    """Parses out important service data to a tuple"""
    state_val = service_dict['current_state']
    if state_val == 0:
        state_name = "OK"
        state_column = 'last_time_ok'
    elif state_val == 1:
        state_name = "WARNING"
        state_column = 'last_time_warning'
    elif state_val == 2:
        state_name = "CRITICAL"
        state_column = 'last_time_critical'
    else:
        state_name = "UNKNOWN"
        state_column = 'last_time_unknown'
    duration = time.time() - service_dict[state_column]
    return (service_dict['host_name'], service_dict['service_description'], state_name, str(duration), "%s/%s" % (service_dict['current_attempt'], service_dict['max_attempts']), service_dict['plugin_output'])

def current_nag_status():
    status = cache.get('nag-status')
    if status is None:
        status = get_nag_status('/root/projects/dashboard/status.dat', 1)
        cache.set('nag-status', status, timeout=10)
    return status

def get_view_data():
    nag_status = current_nag_status()
    crit_services = []
    for host in nag_status.keys():
        for service in nag_status[host].keys():
            if service == 'HOST':
                continue
            crit_services.append("<td>%s</td>" % "</td>\n<td>".join(parse_row(nag_status[host][service])))
    crit_services.sort(key=lambda x: float(x.split('</td>\n<td>')[3]), reverse=True)
    return "<tr>%s</tr>" % "</tr>\n<tr>".join(crit_services)

@app.route("/")
def index():
    return show_view('index')

@app.route("/view/<view_name>")
def show_view(view_name):
    return render_template('view_test.html', nag_status=current_nag_status(), parse_row=parse_row)

if __name__ == "__main__":
    app.run(debug=True, use_debugger=False)
