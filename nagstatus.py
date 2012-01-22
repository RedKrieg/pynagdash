#!/usr/bin/env python

def get_property(line):
    line_split = line.strip().split('=')
    return line_split[0], '='.join(line_split[1:])

def get_nag_status(file):
    """Reads status.dat referred to by [file] and returns a dictionary version of it"""
    status_file = file

    f = open(status_file, 'r')

    line = f.readline()

    host_statuses = {}

    this_host = None
    this_service = None
    group_type = None

    while line:
        if '{' in line:
            group_type = line.strip().split()[0]
        try:
            property, value = get_property(line)
            if group_type == 'hoststatus':
                if property == 'host_name':
                    this_host = value
                    host_statuses[this_host] = {}
                    host_statuses[this_host]['HOST'] = {}
                else:
                    host_statuses[this_host]['HOST'][property] = value
            elif group_type == 'servicestatus':
                if property == 'host_name':
                    this_host = value
                elif property == 'service_description':
                    this_service = value
                    host_statuses[this_host][this_service] = {}
                else:
                    host_statuses[this_host][this_service][property] = value
        except:
            pass
        line = f.readline()
    return host_statuses

if __name__ == "__main__":
    get_nag_status('status.dat')
