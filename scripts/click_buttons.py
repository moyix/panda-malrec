#!/usr/bin/env python

import time
import logging
import string
import listwins
import random
from mon_util import mon_cmd

clickables = set([
    "NEXT", "GO", "INSTALL", "YES", "OK", "DONE",
    "IAGREE", "AGREE", "FINISH", "UPDATE", "IACCEPT",
    "ACCEPT", "DECLINE", "CONTINUE", "RUN", "SAVE",
    "DOWNLOAD", "SKIP",
])

def normalize(s):
    return ''.join(c for c in s if c in string.letters).upper()

def setup(os, sock):
    listwins.setup(os, sock)

def move_to(mon, x, y, absolute=True):
    if absolute:
        # Reset to top-left
        mon_cmd("mouse_move -2000 -2000\n", mon)
        time.sleep(1)
    mon_cmd("mouse_move {0} {1}\n".format(x, y), mon)
    time.sleep(.5)

def click(mon):
    mon_cmd("mouse_button 1\n", mon) # Button 1 down
    time.sleep(.1)
    mon_cmd("mouse_button 0\n", mon) # Button 1 up

def match(s, clickables):
    return s and any((s in c and not abs(len(s)-len(c)) > 10) for c in clickables)

def click_buttons(mon):
    candidates = []
    for w in listwins.get_windows():
        normed = normalize(str(w.strName or ''))
        if match(normed, clickables):
            x1, y1, x2, y2 = map(int, w.rcClient.get_tup())
            clickx, clicky = (x1+x2)/2, (y1+y2)/2
            # Don't click on things that are near the edges
            # Edges here means the outer 10% of the screen
            width, height = 1024, 768
            if (clickx < width * .10 or clickx > width * .90 or
                    clicky < height * .10 or clicky > height * .90):
                continue
            if not w.Visible: continue
            candidates.append( (str(w.strName or ''), clickx, clicky) )

    if not candidates: return

    # If we have multiple, just pick one at random
    (name, clickx, clicky) = random.choice(candidates)
    logging.info("Clicking on %s at (%d,%d)" % (name, clickx, clicky))
    move_to(mon, clickx, clicky)
    click(mon)
