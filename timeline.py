import sys
import sqlite3
import json
from datetime import datetime

class Activity(object):
    
    def __init__(self, application, activity, payload, display_text, description, uri, last_modified_time, start_time, end_time):
        self._application = application
        self._activity = activity
        self._payload = payload
        self._display_text = display_text
        self._description = description
        self._uri = uri
        self._last_modified_time = last_modified_time
        self._start_time = start_time
        self._end_time = end_time
        
    def get_application(self):
        return self._application

    def get_activity(self):
        return self._activity

    def get_payload(self):
        return self._payload

    def get_display_text(self):
        return self_.display_text

    def get_description(self):
        return self._description

    def get_uri(self):
        return self._uri

    def get_last_modified_time(self):
        return self._last_modified_time

    def get_start_time(self):
        return self._start_time

    def get_end_time(self):
        return self._end_time


class Parser(object):
    
    def __init__(self, sql_activities):
        self._sql_activities = sql_activities
        self._activities = list()
        
    def parse(self):
        
        activity_ids = {
            0: 'Unknown',
            1: 'Unknown',
            2: 'Notification',
            3: 'Mobile Device Backup',
            5: 'Open Application/File/Webpage',
            6: 'Application in use/focus',
            7: 'Unknown',
            10: 'Clipboard text',
            11: 'Windows System Operations',
            12: 'Windows System Operations',
            13: 'Unknown',
            15: 'Windows System Operations',
            16: 'Copy/Paste',
        }

        for line in self._sql_activities:

            app_id = json.loads(line[0])
            activity_id = line[1]
            
            try:
                payload = json.loads(str(line[2]))
                display_text = payload.get('displayText', '')
                description = payload.get('description', '')
                uri = payload.get('contentUri', '')
            except ValueError:
                payload = ''
                display_text = ''
                description = ''
                uri = ''

            last_modified_time = line[3]
            start_time = line[4]
            end_time = line[5]

            for app in app_id:
                application = app['application']
                activity = activity_ids.get(activity_id, 'Unknown')
                
                if application:
                    self._activities.append(Activity(application, activity, payload, display_text, description, uri,
                                                     datetime.fromtimestamp(last_modified_time), datetime.fromtimestamp(start_time),
                                                     datetime.fromtimestamp(end_time)))
                    
        return self._activities


if __name__ == '__main__':
    conn = sqlite3.connect(sys.argv[1])
    c = conn.cursor()
    r = c.execute("SELECT AppId, ActivityType, Payload, LastModifiedTime, StartTime, EndTime FROM Activity")

    parser = Parser(r.fetchall())
    activities = parser.parse()
    
    for activity in activities:
        print(activity.get_application())
        print(activity.get_uri())
           
