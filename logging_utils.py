import logging
import sys

import pandas as pd


def logging_info(message, verbose=True):
    logger = logging.getLogger(__name__)
    logger.info(message)
    if verbose:
        print(message)
        sys.stdout.flush()
    return message


def logging_debug(message, verbose=True):
    logger = logging.getLogger(__name__)
    logger.debug(message)
    if verbose:
        print(message)
        sys.stdout.flush()
    return message


def logging_warn(message, verbose=True):
    logger = logging.getLogger(__name__)
    logger.warning("WARNING: " + message)
    if verbose:
        print(message)
        sys.stdout.flush()
    return message


def logging_create(filename, formatted=True):
    # For documentation: read this:
    # https://docs.python.org/3.5/howto/logging.html and
    # https://fangpenlin.com/posts/2012/08/26/good-logging-practice-in-python/
    if formatted:
        logging.basicConfig(
            filename=filename,
            filemode="w",
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )  # overwrite
    else:
        logging.basicConfig(filename=filename, filemode="w", format="%(message)s")
    # Get logger like this
    logger = logging.getLogger(__name__)
    # logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    return logger


def logging_info_table(series_, verbose=True):
    logging_info("# A table count of {}".format(series_.name), verbose)
    logging_info("{}".format(series_.value_counts()), verbose)
    df = pd.DataFrame(series_.value_counts()).reset_index()
    df["var"] = series_.name
    df.columns = ["value", "count", "var"]
    df = df[["var", "value", "count"]]
    return df


def logging_info_percentage(series_, label=None, count_true=True):

    if series_.shape[0] > 0:
        series_sum = series_.sum()
        series_sum_inverse = series_.shape[0] - series_.sum()
        series_percentage = series_sum / series_.shape[0]
        series_percentage_inverse = series_sum_inverse / series_.shape[0]
    else:
        series_sum = 0
        series_percentage = 0
        series_sum_inverse = 0
        series_percentage_inverse = 0

    if count_true:
        if label is None:
            pattern_ = "# {} instances of {}==True out of {} (or {:0.5}%)"
            msg = logging_info(
                pattern_.format(
                    series_sum, series_.name, series_.shape[0], series_percentage * 100
                )
            )
        else:
            pattern_ = "# {} instances of {} ({}==True) out of {} (or {:0.5}%)"
            msg = logging_info(
                pattern_.format(
                    series_sum,
                    label,
                    series_.name,
                    series_.shape[0],
                    series_percentage * 100,
                )
            )

    else:  # count false
        if label is None:
            pattern_ = "# {} instances of {}==False out of {} (or {:0.5}%)"
            msg = logging_info(
                pattern_.format(
                    series_sum_inverse,
                    series_.name,
                    series_.shape[0],
                    series_percentage_inverse * 100,
                )
            )
        else:
            pattern_ = "# {} instances of {} ({}==False) out of {} (or {:0.5}%)"
            msg = logging_info(
                pattern_.format(
                    series_sum_inverse,
                    label,
                    series_.name,
                    series_.shape[0],
                    series_percentage_inverse * 100,
                )
            )
    return msg


class logging_counter(object):
    def __init__(self, max_iter=None, print_at_iter=100, verbose=True):
        self.verbose = verbose
        self.print_at_iter = print_at_iter
        self.counter = 0
        self.max_iter = max_iter

        # Call the function differently
        self.update_counter = self.fit_transform
        return

    def fit_transform(self):
        # Don't border calculating if you are running in silent mode
        if not self.verbose:
            return

        self.counter += 1
        if self.counter % self.print_at_iter == 0:
            if self.max_iter is None:
                logging_info("processing... ", self.counter)
            else:
                logging_info(
                    "# processing... {} of {}".format(self.counter, self.max_iter)
                )
        return
