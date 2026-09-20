# Copyright (c) 2024 Finite State, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""What counts as a CVSS vector string.

The NVD client and the Findings by Project transform both have to answer this,
at opposite ends of the same pipeline: the client picks one entry out of a
metrics list, and the transform picks one field out of the enrichment it
produced. Two copies of the rule would let them disagree about the same string
— the client handing back a placeholder the transform then drops, with the real
vector already discarded — so the rule lives here and both import it.
"""

import re

# At least one slash-separated metric field: ``AV:N``, ``S:U``, ``Au:N``.
#
# Deliberately loose about metric names, version and field order, because the
# column prints vectors as published and a vector fs-report does not recognize
# is still a vector. It only has to rule out text that is no version's vector:
# a placeholder (``n/a``, ``unknown``, ``-``), a bare prefix (``CVSS:3.1`` with
# nothing after it), or a free-text note.
CVSS_METRIC_FIELD = re.compile(r"(?:^|[/\s,;])[A-Za-z]{1,2}:[A-Za-z]")


def looks_like_vector(text: str) -> bool:
    """True when the text carries at least one CVSS metric field."""
    return bool(CVSS_METRIC_FIELD.search(text))
