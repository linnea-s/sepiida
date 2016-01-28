_config = None

def reload():
    from twisted.python import log
    import ConfigParser
    config = ConfigParser.RawConfigParser()
    
    config.readfp(open('/etc/sepiida/agent.conf'))
    required = { 'Agent':
                ('login cmd', 'log debug', 'resolve ips'),
                'Commands':
                ('vnc proxy', 'vnc notify', 'send message', 'logout', 'lock screen')
            }
    err = False
    for section in required:
        if not config.has_section(section):
            log.msg('configuration file missing section %s' % section)
            err = True
            continue
        for key in required[section]:
            if not config.has_option(section, key):
                log.msg('configuration file missing option %s in section %s' % (key, section))
                err = True
    if err:
        raise Exception('configuration file missing one or more sections/options')
    
    config.set('Commands', 'open url', '/usr/bin/xdg-open ${url}')
    global _config
    _config = config

def get():
    return _config