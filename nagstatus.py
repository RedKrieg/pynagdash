#!/usr/bin/env python
import time

def get_property(line):
    line_split = line.strip().split('=')
    #returns the property name and remaining data recombined after the split above
    if len(line_split) < 2:
        raise Exception("Line is not a key/value pair.")
    #Ensures that all characters are valid unicode strings
    return line_split[0].encode('utf-8', 'ignore'), u'='.join(line_split[1:])

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
                    host_statuses[this_host]['HOST']['service_comments'] = {}
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
                    host_statuses[this_host][this_service]['service_comments'] = {}
                else:
                    host_statuses[this_host][this_service][this_property] = try_to_convert(value)
                    if this_property == 'current_state' and host_statuses[this_host][this_service][this_property] < threshold:
                        #by simply removing the service here, subsequent attempts to add data fail to the next loop iteration
                        del host_statuses[this_host][this_service]
                    elif this_property == 'last_state_change':
                        host_statuses[this_host][this_service]['current_duration'] = time.time() - try_to_convert(value)
            elif group_type == 'servicecomment':
                if this_property == 'host_name':
                    this_host = value
                elif this_property == 'service_description':
                    this_service = value
                elif this_property == 'entry_type':
                    # Need to hang on to this one for one more line
                    this_entry_type = try_to_convert(value)
                elif this_property == 'comment_id':
                    this_comment_id = value
                    host_statuses[this_host][this_service]['service_comments'][value] = {
                        'entry_type': this_entry_type,
                        'comment_id': this_comment_id
                    }
                else:
                    host_statuses[this_host][this_service]['service_comments'][this_comment_id][this_property] = try_to_convert(value)
            elif group_type == 'hostcomment':
                if this_property == 'host_name':
                    this_host = value
                    this_service = 'HOST'
                elif this_property == 'entry_type':
                    # Need to hang on to this one for one more line
                    this_entry_type = try_to_convert(value)
                elif this_property == 'comment_id':
                    this_comment_id = value
                    host_statuses[this_host][this_service]['service_comments'][value] = {
                        'entry_type': this_entry_type,
                        'comment_id': this_comment_id
                    }
                else:
                    host_statuses[this_host][this_service]['service_comments'][this_comment_id][this_property] = try_to_convert(value)
        except:
            pass
    f.close()
    return host_statuses

if __name__ == "__main__":
    #simply me testing, this chunk is not needed
    status = get_nag_status('status.dat', 0)
    import json
    print json.dumps(status, indent=4)
