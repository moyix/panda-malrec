import logging
import time
import string

keymap = {
    '-': 'minus',
    '=': 'equal',
    '[': 'bracket_left',
    ']': 'bracket_right',
    ';': 'semicolon',
    '\'': 'apostrophe',
    '\\': 'backslash',
    ',': 'comma',
    '.': 'dot',
    '/': 'slash',
    '*': 'asterisk',
    ' ': 'spc',
    '_': 'shift-minus',
    '+': 'shift-equal',
    '{': 'shift-bracket_left',
    '}': 'shift-bracket_right',
    ':': 'shift-semicolon',
    '"': 'shift-apostrophe',
    '|': 'shift-backslash',
    '<': 'shift-comma',
    '>': 'shift-dot',
    '?': 'shift-slash',
    '\n': 'ret',
}

def mon_cmd(s, mon):
    mon.write(s)
    logging.info(mon.read_until("(qemu)"))

def guest_type(s, mon):
    for c in s:
        if c in string.ascii_uppercase:
            key = 'shift-' + c.lower()
        else:
            key = keymap.get(c, c)
        mon_cmd('sendkey {0}\n'.format(key), mon)
        time.sleep(.1)
