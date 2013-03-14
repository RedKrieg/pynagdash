#!/usr/bin/env python
import time

def get_property(line):
    line_split = line.strip().split('=')
    #returns the property name and remaining data recombined after the split above
    if len(line_split) < 2:
        raise Exception("Line is not a key/value pair.")
    return line_split[0], '='.join(line_split[1:])

def try_to_convert(value):
    """Tries to convert [value] to an int, returns the original string on fail"""
    try:
        return int(value)
    except:
        return value

def get_nag_status(filename, threshold = 0):
    """Reads status.dat referred to by [filename] and returns a dictionary version of it"""
    status_file = filename

    f = open(status_file, 'r')

    line = f.readline()

    host_statuses = {}

    this_host = None
    this_service = None
    group_type = None

    for line in f:
        if line.strip().endswith('{'):
            group_type = line.strip().split()[0]
            continue
        try:
            this_property, value = get_property(line) #fails on lines without =, the try makes us pass
            #not yet reading programstatus or info
            if group_type == 'hoststatus':
                if this_property == 'host_name':
                    this_host = value
                    host_statuses[this_host] = {}
                    host_statuses[this_host]['HOST'] = {}
                else:
                    host_statuses[this_host]['HOST'][this_property] = try_to_convert(value)
            elif group_type == 'servicestatus':
                #host_name always comes before service_description
                if this_property == 'host_name':
                    this_host = value
                elif this_property == 'service_description':
                    this_service = value
                    host_statuses[this_host][this_service] = {}
                    host_statuses[this_host][this_service][this_property] = value #handy place to have the service description and host name
                    host_statuses[this_host][this_service]['host_name'] = this_host
                else:
                    host_statuses[this_host][this_service][this_property] = try_to_convert(value)
                    if this_property == 'current_state' and host_statuses[this_host][this_service][this_property] < threshold:
                        #by simply removing the service here, subsequent attempts to add data fail to the next loop iteration
                        del host_statuses[this_host][this_service]
                    elif this_property == 'last_state_change':
                        host_statuses[this_host][this_service]['current_duration'] = time.time() - try_to_convert(value)
        except:
            pass
    f.close()
    return host_statuses

if __name__ == "__main__":
    #simply me testing, this chunk is not needed
    print get_nag_status('status.dat', 1)
