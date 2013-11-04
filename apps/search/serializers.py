from rest_framework import serializers, pagination

from .fields import SearchQueryField, DocumentExcerptField
from .models import Filter


class FacetSerializer(serializers.Serializer):
    name = serializers.CharField(read_only=True)
    slug = serializers.CharField(read_only=True)
    count = serializers.IntegerField(read_only=True)
    enabled = serializers.BooleanField(read_only=True)
    url_enabled = serializers.Field(read_only=True)
    url_disabled = serializers.Field(read_only=True)


class SearchSerializer(pagination.PaginationSerializer):
    results_field = 'documents'

    query = SearchQueryField(source='*')
    page = serializers.Field(source='number')
    pages = serializers.Field(source='paginator.num_pages')
    facets = FacetSerializer(source='paginator.object_list.facet_list',
                             many=True)


class DocumentSerializer(serializers.Serializer):
    title = serializers.CharField(read_only=True, max_length=255)
    slug = serializers.CharField(read_only=True, max_length=255)
    locale = serializers.CharField(read_only=True, max_length=7)
    excerpt = DocumentExcerptField(source='*')
    url = serializers.CharField(read_only=True, source='get_url')
    tags = serializers.ChoiceField(read_only=True, source='tags')


class FilterSerializer(serializers.ModelSerializer):
    tags = serializers.ChoiceField(source='tags.all', read_only=True)

    class Meta:
        model = Filter
        depth = 1
        fields = ('name', 'slug', 'tags')
        read_only_fields = ('name', 'slug')
