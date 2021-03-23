from datetime import datetime, timedelta
from threading import Thread
from time import sleep

class Timer(Thread):
    def __init__(self, delay, function):

        super(Timer, self).__init__()
        self._state = True
        self.delay = delay
        self.function = function

    def stop(self):
        self._state = False

    def run(self):
        hour = datetime.now() + timedelta(seconds=1)
        if hour <= datetime.now():
            hour += timedelta(seconds=self.delay)

        while self._state:
            if hour <= datetime.now():
                self.function()
                hour += timedelta(seconds=self.delay)

            sleep(1)
