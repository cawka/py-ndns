# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
VERSION='0.1'
APPNAME='ndns'

def options(opt):
    opt.load('compiler_c python gnu_dirs')

def configure(conf):
    conf.load("compiler_c python gnu_dirs")

    conf.check_python_version ((2,7))
    conf.check_python_headers ()

    conf.check_python_module ('daemon')
    conf.check_python_module ('apscheduler')
    conf.check_python_module ('sqlalchemy')

    try:
        conf.start_msg ("Check contrib/")

        import subprocess
        from waflib import Logs
        p = subprocess.Popen("git submodule status", shell=True, stdout=subprocess.PIPE)
        var = p.communicate ()[0]

        up_to_date = True
        for line in var.split ('\n'):
            if line == "":
                continue
            up_to_date = (up_to_date and line[0] == ' ')

        if up_to_date:
            conf.end_msg ("up-to-date")
        else:
            conf.end_msg ("contrib/ has differences, consider `git submodule update` or `git submodule update --init`", 'YELLOW')
            Logs.warn (var)
    except:
        raise

    try:
        conf.check_python_module ('setproctitle')
    except:
        from waflib import Logs
        Logs.warn ("py-setproctitle can be installed from contrib/ folder: (cd contrib/py-setproctitle && sudo python ./setup.py install)")
        raise

def build (bld):
    pass
