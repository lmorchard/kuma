from __future__ import absolute_import
from nose.tools import eq_, ok_

from test_utils import TestCase

from search.store import referrer_url
from search.utils import QueryURLObject


class URLTests(TestCase):

    def test_pop_query_param(self):
        original = 'http://example.com/?spam=eggs'
        url = QueryURLObject(original)

        eq_(url.pop_query_param('spam', 'eggs'), 'http://example.com/')
        eq_(url.pop_query_param('spam', 'spam'), original)

        original = 'http://example.com/?spam=eggs&spam=spam'
        url = QueryURLObject(original)
        eq_(url.pop_query_param('spam', 'eggs'),
            'http://example.com/?spam=spam')
        eq_(url.pop_query_param('spam', 'spam'),
            'http://example.com/?spam=eggs')

    def test_merge_query_param(self):
        original = 'http://example.com/?spam=eggs'
        url = QueryURLObject(original)

        eq_(url.merge_query_param('spam', 'eggs'), original)
        eq_(url.merge_query_param('spam', 'spam'), original + '&spam=spam')


    def test_referer_bad_encoding(self):
        class _TestRequest(object):
            # In order to test this we just need an object that has
            # 'locale' and 'META', but not the full attribute set of
            # an HttpRequest. This is that object.
            def __init__(self, locale, referer):
                self.locale = locale
                self.META = {'HTTP_REFERER': referer}

        request = _TestRequest('es', 'http://developer.mozilla.org/es/docs/Tutorial_de_XUL/A\xc3\x83\xc2\xb1adiendo_botones')
        ok_(referrer_url(request) is None)
        
