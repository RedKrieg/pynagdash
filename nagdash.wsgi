import sys, os, inspect
#sys.path.insert(0, '/home/rkutilus/public_html/dashboard')
sys.path.insert(0, os.path.dirname(inspect.getfile(inspect.currentframe())))
from nagdash import app as application
