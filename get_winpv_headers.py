#!python -u

import os, sys
import shutil
import subprocess
import re

def shell(command, dir = '.'):
    print("in '%s' execute '%s'" % (dir, ' '.join(command)))
    sys.stdout.flush()

    sub = subprocess.Popen(command, cwd=dir,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)

    for line in sub.stdout:
        print(line.decode(sys.getdefaultencoding()).rstrip())

    sub.wait()

    return sub.returncode

def get_repo(url, working):
    shell(['git', 'clone', '--no-checkout', url, working])

def get_branch(tag, working):
    shell(['git', 'checkout', '-b', 'tmp', tag], working)

def put_branch(working):
    shell(['git', 'checkout', 'master'], working)
    shell(['git', 'branch', '-d', 'tmp'], working)

def copy_file(working, dirlist, name):
    parts = [working] + dirlist + [name]
    srcpath = os.path.join(*parts)

    parts = ['include', 'ks', 'platform', 'windows']
    dstdirpath = os.path.join(*parts)
    parts.append(name)
    dstpath = os.path.join(*parts)

    try:
        print('creating:', dstdirpath)
        os.makedirs(dstdirpath)
    except OSError:
        None

    src = open(srcpath, 'r')
    dst = open(dstpath, 'w', newline='\n')

    print('%s -> %s' % (srcpath, dstpath))

    for line in src:
        line = re.sub(' unsigned long', ' ULONG_PTR', line)
        line = re.sub('\(unsigned long', '(ULONG_PTR', line)
        line = re.sub(' long', ' LONG_PTR', line)
        line = re.sub('\(long', '(LONG_PTR', line)
        dst.write(line)

    dst.close()
    src.close()

if __name__ == '__main__':
    tag = sys.argv[1]
    working = 'xenbus'

    get_repo('git://xenbits.xen.org/pvdrivers/win/xenbus.git', working)
    get_branch(tag, working)

    copy_file(working, ['include'], 'cache_interface.h')
    copy_file(working, ['include'], 'debug_interface.h')
    copy_file(working, ['include'], 'evtchn_interface.h')
    copy_file(working, ['include'], 'gnttab_interface.h')
    copy_file(working, ['include'], 'store_interface.h')

    put_branch(working)
