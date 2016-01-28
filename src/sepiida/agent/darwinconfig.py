_config = None
def reload():
    from ConfigParser import RawConfigParser
    config = RawConfigParser()
    f = open('/etc/sepiida-agent.conf', 'rb')
    config.readfp(f)
    global _config
    _config = config

def get():
    return _config

