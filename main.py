from genKeys import genKeys
from genBase import genBase
from pyHIDS import pyHIDS
from timer import Timer
import conf

genKeys()
genBase()

t = Timer(conf.TIMER, pyHIDS)
t.start()