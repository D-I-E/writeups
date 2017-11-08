import os
import sys


if not os.path.exists(sys.argv[1]):
    os.mkdir(sys.argv[1])
if not os.path.exists(os.path.join(sys.argv[1],sys.argv[2])):
    os.mkdir(os.path.join(sys.argv[1],sys.argv[2]))
if not os.path.exists(os.path.join(sys.argv[1],sys.argv[2],'readme.md')):
    f = open(os.path.join(sys.argv[1],sys.argv[2],'readme.md'), 'w')

    f.write('''# poc\n\n(TODO)\n\n# exp\n\n(TODO)\n''')
    f.close()

