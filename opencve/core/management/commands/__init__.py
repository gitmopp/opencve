from pyexpat.errors import messages
import time
from contextlib import contextmanager

import arrow

from django.core.management.base import BaseCommand as DjangoBaseCommand


class BaseCommand(DjangoBaseCommand):
    CURRENT_YEAR = arrow.now().year
    CVE_FIRST_YEAR = 2022

    def error(self, message, ending=None):
        self.stdout.write(f"[error] {message}", ending=ending)

    def header(self, message):
        self.stdout.write("#" * len(message))
        self.stdout.write(message)
        self.stdout.write("#" * len(message))

    def info(self, message, ending=None):
        self.stdout.write(f"[*] {message}", ending=ending)

    @contextmanager
    def timed_operation(self, msg, ending=None):
        start = time.time()
        self.info(msg, ending=ending)
        yield
        self.info(" (done in {}s).".format(round(time.time() - start, 3)))
