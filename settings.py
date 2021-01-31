# Sinks
network = ['Servlet', 'web', 'URL', 'apache', 'http', 'OAuth2', 'socket', 'rpc', 'spring']
database = ['createQuery', 'sql', 'Jdbc']
files = ['File', 'Writer', 'OutputStream']
logs = ['print', 'Log', 'OutputStream']
components = ['Bundle', 'Intent', 'Activity']
message = ['Sms', 'Message']
video = ['media']

sinks_categories = {'network': network, 'database': database, 'files': files,
                    'logs': logs, 'components': components, 'message': message, 'media': video}

# Sources
location = ['Location', 'locale', 'timezone']
phone_id = ['Telephony', 'device']
bluetooth = ['Bluetooth']
Audio = ['Audio']
installed_apps = ['Package']
wifi = ['wifi']
personal = ['Calendar']
log_source = ['logs']
credentails = ['authentication', 'Login', 'oauth2', 'security']
db = ['database', 'sql']

sensors = ['sensor']
account = ['account']
calendar = ['Calendar']
Browser = ['Browser']

sources_categories = {'credentails': credentails, 'location': location,
                      'phone_id': phone_id, 'Audio': Audio,
                      'installed_apps': installed_apps, 'bluetooth': bluetooth,
                      'wifi': wifi, 'personal': personal, 'db': db, 'sensors': sensors, 'account': account,
                      'calendar': calendar, 'browser': Browser
                      }
