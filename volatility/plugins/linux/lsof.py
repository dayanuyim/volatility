# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
"""



import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers.basic import Address
from volatility.renderers import TreeGrid

class linux_lsof(linux_pslist.linux_pslist):
    """Lists file descriptors and their path"""

    """fmode bitwise, copy from linux/fs.h"""
    FMODE_READ		  = 0x1
    FMODE_WRITE		  = 0x2
    FMODE_LSEEK		  = 0x4
    FMODE_PREAD		  = 0x8
    FMODE_PWRITE	  = 0x10
    FMODE_EXEC		  = 0x20
    FMODE_NDELAY          = 0x40
    FMODE_EXCL		  = 0x80
    FMODE_WRITE_IOCTL	  = 0x100
    FMODE_32BITHASH       = 0x200
    FMODE_64BITHASH       = 0x400
    FMODE_NOCMTIME	  = 0x800
    FMODE_RANDOM	  = 0x1000
    FMODE_UNSIGNED_OFFSET = 0x2000
    FMODE_PATH		  = 0x4000
    FMODE_ATOMIC_POS	  = 0x8000
    FMODE_WRITER	  = 0x10000
    FMODE_CAN_READ        = 0x20000
    FMODE_CAN_WRITE       = 0x40000
    FMODE_NONOTIFY	  = 0x4000000

    def unified_output(self, data):
        return TreeGrid([("Offset",Address),
                         ("Name",str),
                        ("Pid", int),
                       ("FD", int),
                       ("Path", str)],
                        self.generator(data))

    def generator(self, data):
        for task in data:
            for filp, fd in task.lsof():
                yield (0, [Address(task.obj_offset),str(task.comm),int(task.pid), int(fd), str(linux_common.get_path(task, filp))])


    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset","#018x"),
                                  ("Name","30"),
                                  ("Pid", "8"),
                                  ("FD", "8"),
                                  ("Mode", "15"),
                                  ("Path", ""),
                                  ])

        for task in data:
            for filp, fd in task.lsof(): 
                self.table_row(outfd,
                        Address(task.obj_offset),
                        str(task.comm),
                        task.pid,
                        fd,
                        self.__toModeText(filp.f_mode),
                        linux_common.get_path(task, filp))

    def __toModeText(self, fmode):
        tokens = []
        tokens.append('r' if fmode & self.FMODE_READ else '-')
        tokens.append('w' if fmode & self.FMODE_WRITE else '-')
        tokens.append('x' if fmode & self.FMODE_EXEC else '-')

        return ''.join(tokens)
