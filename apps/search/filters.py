import operator
from elasticutils import Q
from elasticutils.contrib.django import F

from rest_framework.filters import BaseFilterBackend

from wiki.models import DocumentType


class LanguageFilterBackend(BaseFilterBackend):

    def filter_queryset(self, request, queryset, view):
        return queryset.filter(locale=request.locale)


class SearchQueryBackend(BaseFilterBackend):
    search_param = 'q'
    search_field = ['title', 'content', 'summary']

    def filter_queryset(self, request, queryset, view):
        search_param = request.QUERY_PARAMS.get(self.search_param, None)

        if search_param:
            query = {}
            for field in self.search_field:
                query[field + '__text'] = search_param
            queryset = queryset.query(Q(should=True, **query))
        return queryset


class HighlightFilterBackend(BaseFilterBackend):
    highlight_fields = DocumentType.excerpt_fields

    def filter_queryset(self, request, queryset, view):
        return queryset.highlight(*self.highlight_fields)


class StoredFilterBackend(BaseFilterBackend):
    def filter_queryset(self, request, queryset, view):
        enabled_filters = []
        enabled_facets = []

        for stored_filter in view.stored_filters:
            filter_tags = stored_filter['tags']

            if stored_filter['slug'] in view.current_topics:

                if len(filter_tags) > 1:
                    tag_filters = []
                    for filter_tag in filter_tags:
                        tag_filters.append(F(tags=filter_tag.lower()))
                    enabled_filters.append(reduce(operator.or_, tag_filters))
                else:
                    enabled_filters.append(F(tags=filter_tags[0].lower()))

            if len(filter_tags) > 1:
                facet_params = {
                    'or': {
                        'filters': [
                            {'term': {'tags': tag.lower()}}
                            for tag in filter_tags
                        ],
                        '_cache': True,
                    },
                }
            else:
                facet_params = {
                    'term': {'tags': filter_tags[0].lower()}
                }
            enabled_facets.append((stored_filter['slug'], facet_params))

        if view.drilldown_faceting:
            filter_operator = operator.and_
        else:
            filter_operator = operator.or_

        unfiltered_queryset = queryset
        if enabled_filters:
            queryset = queryset.filter(reduce(filter_operator, enabled_filters))

        # only way to get to the currently applied filters
        # to use it to limit the facets filters below
        if view.drilldown_faceting:
            facet_filter_queryset = queryset._build_query().get('filter', [])
        else:
            facet_filter_queryset = unfiltered_queryset._build_query().get('filter', [])

        for facet_slug, facet_params in enabled_facets:
            facet_query = {
                facet_slug: {
                    'filter': facet_params,
                    'facet_filter': facet_filter_queryset,
                }
            }
            queryset = queryset.facet_raw(**facet_query)

        return queryset
