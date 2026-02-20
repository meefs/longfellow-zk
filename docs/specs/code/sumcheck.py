import math

import fields


def bindeq(field, log_n, challenges):
    if log_n == 0:
        return [field.one()]
    n = 2 ** log_n
    b = [None] * n
    a = bindeq(field, log_n - 1, challenges[1:])
    for i in range(n // 2):
        b[2 * i] = (field.one() - challenges[0]) * a[i]
        b[2 * i + 1] = challenges[0] * a[i]
    return b
