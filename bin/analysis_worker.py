#!/usr/bin/env python3

'''Runs the queued analyses (urlabuse/analysis.py). Several analyses run at
the same time, and the providers of an analysis run in parallel.'''

from __future__ import annotations

import logging
import logging.config

from concurrent.futures import ThreadPoolExecutor

from urlabuse.analysis import Analyses
from urlabuse.cache import Cache
from urlabuse.default import AbstractManager, get_config
from urlabuse.providers import Providers

logging.config.dictConfig(get_config('logging'))


class AnalysisWorker(AbstractManager):

    def __init__(self, loglevel: int | None=None) -> None:
        super().__init__(loglevel)
        self.script_name = 'analysis_worker'
        self.analyses = Analyses(Providers(Cache()))
        workers = get_config('generic', 'analysis_workers')
        # One thread per running analysis + a shared pool for the provider calls
        self.analysis_pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='analysis')
        self.provider_pool = ThreadPoolExecutor(max_workers=workers * 8, thread_name_prefix='provider')

    def _to_run_forever(self) -> None:
        while (analysis_uuid := self.analyses.next_queued()):
            self.logger.info(f'Starting analysis {analysis_uuid}')
            self.analysis_pool.submit(self.analyses.run, analysis_uuid, self.provider_pool)

    def _wait_to_finish(self) -> None:
        self.analysis_pool.shutdown(wait=True, cancel_futures=False)
        self.provider_pool.shutdown(wait=True)
        super()._wait_to_finish()


def main() -> None:
    AnalysisWorker().run(sleep_in_sec=1)


if __name__ == '__main__':
    main()
