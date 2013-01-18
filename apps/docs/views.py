import json
import os.path
import random

from django.conf import settings
from django.http import (HttpResponseRedirect)

from caching.base import cached
import commonware
from dateutil.parser import parse as date_parse
import jingo
from tower import ugettext as _

from feeder.models import Entry

from wiki.models import Document, REVIEW_FLAG_TAGS

log = commonware.log.getLogger('kuma.docs')

MAX_REVIEW_DOCS = 5


def docs(request):
    """Docs landing page."""

    # Accept ?next parameter for redirects from language selector.
    if 'next' in request.GET:
        next = request.GET['next']
        # Only accept site-relative paths, not absolute URLs to anywhere.
        if next.startswith('/'):
            return HttpResponseRedirect(next)

    # Doc of the day
    dotd = cached(_get_popular_item, 'kuma_docs_dotd', 24*60*60)

    # Recent updates
    active_docs = []

    review_flag_docs = dict()
    for tag, description in REVIEW_FLAG_TAGS:
        review_flag_docs[tag] = (Document.objects
            .filter_for_review(tag_name=tag)
            .order_by('-current_revision__created')
            .all()[:MAX_REVIEW_DOCS])

    data = {'active_docs': active_docs, 
            'review_flag_docs': review_flag_docs,
            'dotd': dotd}
    return jingo.render(request, 'docs/docs.html', data)


def _get_popular_item():
    """Get a single, random item off the popular pages list."""
    # FIXME: This does nothing since MindTouch went away
    return None
