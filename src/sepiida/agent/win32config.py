_config = None
def reload():
    from ConfigParser import RawConfigParser
    import os
    config = RawConfigParser()
    f = open(os.path.join('c:\\', 'sepiida', 'agent.ini'))
    config.readfp(f)
    global _config
    _config = config

def get():
    return _config