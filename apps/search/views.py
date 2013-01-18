import time
import re
import json
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.sites.models import Site
from django.db.models import ObjectDoesNotExist
from django.http import HttpResponse, HttpResponseBadRequest
from django.utils.http import urlencode
from django.views.decorators.cache import cache_page

import jingo
import jinja2
from tower import ugettext as _

from sumo.utils import paginate, smart_int
from wiki.models import Document, FIREFOX_VERSIONS, OPERATING_SYSTEMS


def jsonp_is_valid(func):
    func_regex = re.compile(r'^[a-zA-Z_\$][a-zA-Z0-9_\$]*'
        + r'(\[[a-zA-Z0-9_\$]*\])*(\.[a-zA-Z0-9_\$]+(\[[a-zA-Z0-9_\$]*\])*)*$')
    return func_regex.match(func)

@cache_page(60 * 15)  # 15 minutes.
def suggestions(request):
    """Return empty array until we restore internal search system."""

    mimetype = 'application/x-suggestions+json'

    term = request.GET.get('q')
    if not term:
        return HttpResponseBadRequest(mimetype=mimetype)

    results = []
    return HttpResponse(json.dumps(results), mimetype=mimetype)


@cache_page(60 * 60 * 168)  # 1 week.
def plugin(request):
    """Render an OpenSearch Plugin."""
    site = Site.objects.get_current()
    return jingo.render(request, 'search/plugin.html',
                        {'site': site, 'locale': request.locale},
                        mimetype='application/opensearchdescription+xml')
