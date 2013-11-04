import json
from collections import namedtuple
from operator import attrgetter

from django.contrib.sites.models import Site
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import render
from django.views.decorators.cache import cache_page
from django.utils.functional import cached_property
from django.utils.datastructures import SortedDict

from elasticutils.contrib.django import S
from rest_framework.generics import ListAPIView
from rest_framework.renderers import TemplateHTMLRenderer, JSONRenderer
from tower import ugettext_lazy as _lazy
from waffle import flag_is_active

from wiki.models import DocumentType

from .filters import (LanguageFilterBackend, StoredFilterBackend,
                      SearchQueryBackend, HighlightFilterBackend)
from .models import Filter
from .serializers import SearchSerializer, DocumentSerializer, FilterSerializer
from .utils import QueryURLObject


class Facet(namedtuple('Facet',
                       ['name', 'slug', 'count', 'url', 'page', 'enabled'])):
    __slots__ = ()

    def pop_page(self, url):
        return str(url.pop_query_param('page', str(self.page)))

    @cached_property
    def url_enabled(self):
        return self.pop_page(self.url.merge_query_param('topic', self.slug))

    @cached_property
    def url_disabled(self):
        return self.pop_page(self.url.pop_query_param('topic', self.slug))


class DocumentS(S):
    """
    This S object acts more like Django's querysets to better match
    the behavior of restframework's serializers.
    """
    def __init__(self, *args, **kwargs):
        self.url = kwargs.pop('url', None)
        self.current_page = kwargs.pop('current_page', None)
        self.filters = kwargs.pop('filters', None)
        self.topics = kwargs.pop('topics', None)
        super(DocumentS, self).__init__(*args, **kwargs)

    def _clone(self, next_step=None):
        new = super(DocumentS, self)._clone(next_step)
        new.url = self.url
        new.current_page = self.current_page
        new.filters = self.filters
        new.topics = self.topics
        return new

    def all(self):
        """
        The serializer calls the ``all`` method for "all items" of the queryset,
        while elasticutils considers the method to return "all results" of the
        search, which ignores pagination etc.

        Iterating over self is the same as in Django's querysets' all method.
        """
        return self

    def facet_list(self):
        facets = []
        url = QueryURLObject(self.url)
        for slug, facet in self.facet_counts().items():
            if not isinstance(facet, dict):
                # let's just blankly ignore any non-filter or non-query facets
                continue
            filter_ = self.filters.get(slug, None)
            if filter_ is None:
                name = slug
            else:
                # Let's check if we can get the name from the gettext catalog
                name = _lazy(filter_['name'])
            facet = Facet(url=url,
                          page=self.current_page,
                          name=name,
                          slug=slug,
                          count=facet.get('count', 0),
                          enabled=slug in self.topics)
            facets.append(facet)
        # return a sorted set of facets here
        return sorted(facets, key=attrgetter('name'))


class SearchView(ListAPIView):
    http_method_names = ['get']
    serializer_class = DocumentSerializer
    renderer_classes = (
        TemplateHTMLRenderer,
        JSONRenderer,
    )
    #: list of filters to applies in order of listing, each implementing
    #: the specific search feature
    filter_backends = (
        LanguageFilterBackend,
        SearchQueryBackend,
        HighlightFilterBackend,
        StoredFilterBackend,
    )
    paginate_by = 10
    max_paginate_by = 100
    paginate_by_param = 'per_page'
    pagination_serializer_class = SearchSerializer
    topic_param = 'topic'

    @cached_property
    def drilldown_faceting(self):
        return flag_is_active(self.request, 'search_drilldown_faceting')

    @cached_property
    def stored_filters(self):
        return FilterSerializer(Filter.objects.all(), many=True).data

    @cached_property
    def current_topics(self):
        seen = set()
        topics = self.request.QUERY_PARAMS.getlist(self.topic_param, [])
        return [topic
                for topic in topics
                if topic not in seen and not seen.add(topic)]

    def get_template_names(self):
        return ['search/results-redesign.html']

    def get_queryset(self):
        return DocumentS(
            DocumentType,
            url=self.request.get_full_path(),
            current_page=self.request.QUERY_PARAMS.get(self.page_kwarg, 1),
            filters=SortedDict((filter['slug'], filter)
                               for filter in self.stored_filters),
            topics=self.current_topics
        )

search = SearchView.as_view()


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
    return render(request, 'search/plugin.html', {
        'site': site,
        'locale': request.locale
    }, content_type='application/opensearchdescription+xml')
