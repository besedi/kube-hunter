import logging
import os
import requests
import sys

from kube_hunter.conf import config

logger = logging.getLogger(__name__)


class HTTPDispatcher(object):
    def dispatch(self, report):
        logger.debug("Dispatching report via HTTP")
        dispatch_method = os.environ.get(
            'KUBEHUNTER_HTTP_DISPATCH_METHOD',
            'POST'
        ).upper()
        dispatch_url = os.environ.get(
            'KUBEHUNTER_HTTP_DISPATCH_URL',
            'https://localhost/'
        )
        try:
            r = requests.request(
                dispatch_method,
                dispatch_url,
                json=report,
                headers={'Content-Type': 'application/json'}
            )
            r.raise_for_status()
            logger.info(f"Report was dispatched to: {dispatch_url}")
            logger.debug(f"Dispatch responded {r.status_code} with: {r.text}")

        except requests.HTTPError as e:
            # specific http exceptions
            logger.exception(f"Failed making HTTP {dispatch_method} to {dispatch_url}, status code {r.status_code}")
        except Exception as e:
            # default all exceptions
            logger.exception(f"Could not dispatch report using HTTP {dispatch_method} to {dispatch_url}")


class STDOUTDispatcher(object):
    def dispatch(self, report):
        logger.debug("Dispatching report via stdout")
        print(report)


class FILEDispatcher(object):
    def dispatch(self, report):
        logger.debug("Dispatching report via python object")
        dispatch_file = os.environ.get(
            'KUBEHUNTER_FILE_DISPATCH_PATH',
            'hunting.report'
        )
        with open(os.path.join(sys.path[0], dispatch_file), mode='w') as f:
            full_report_path = f.name
            f.write(report)
            logger.info(f'Report was saved in "{full_report_path}"')
