from nose.tools import ok_, eq_

from search.models import Filter, FilterGroup
from search.tests import ElasticTestCase, factory
from wiki.models import DocumentType

from test_utils import TestCase

from search.views import DocumentS
from search.serializers import FilterSerializer, DocumentSerializer
from search.fields import DocumentExcerptField, SearchQueryField


class SerializerTests(ElasticTestCase):
    fixtures = ['test_users.json', 'wiki/documents.json']

    def test_filter_serializer(self):
        group = FilterGroup.objects.create(name='Group')
        filter_ = Filter.objects.create(name='Serializer', slug='serializer',
                                        group=group)
        filter_.tags.add('tag')
        filter_serializer = FilterSerializer(filter_)
        eq_({'name': u'Serializer', 'slug': u'serializer', 'tags': ['tag']},
            filter_serializer.data)

    def test_document_serializer(self):
        doc = DocumentS(DocumentType)
        doc_serializer = DocumentSerializer(doc)
        list_data = doc_serializer.data
        eq_(len(list_data), 6)
        ok_(isinstance(list_data, list))
        eq_(list_data[0]['title'], 'le title')

        doc_serializer = DocumentSerializer(doc[0], many=False)
        dict_data = doc_serializer.data
        ok_(isinstance(dict_data, dict))
        eq_(dict_data['title'], 'le title')


class FieldTests(TestCase):

    def test_DocumentExcerptField(self):

        class FakeValue(DocumentType):
            _highlight = {'content': ['<b>this</b> is <em>matching</em> text']}

        field = DocumentExcerptField()
        eq_(field.to_native(FakeValue()), 'this is <em>matching</em> text')

    def test_SearchQueryField(self):
        fake_request = factory.get('/?q=test')
        # APIRequestFactory doesn't actually return APIRequest objects
        # but standard HttpRequest objects due to the way it initializes
        # the request when APIViews are called
        fake_request.QUERY_PARAMS = fake_request.GET

        field = SearchQueryField()
        field.context = {'request': fake_request}
        eq_(field.to_native(None), 'test')
