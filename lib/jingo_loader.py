"""
This is a Django-compatible template loader for jingo.

The newest version of jingo comes with a different & better implementation of
this, but MDN isn't quite ready for an upgrade.
"""
from django.conf import settings

try:
    # If we happen to have upgraded to the latest jingo, use the loader it
    # comes with and skip our cruddy implementation.
    from jingo import Loader

except ImportError, e:

    import jinja2
    from jingo import env
    from django.template import TemplateDoesNotExist
    from django.template.loader import BaseLoader

    EXCLUDE_APPS = (
        'admin',
        'admindocs',
        'registration',
    )

    class AdapterTemplate(object):

        def __init__(self, template):
            self.template = template
            self.filename = template.filename

        def render(self, context={}):
            """Render's a template, context can be a Django Context or a
            dictionary.
            """
            from django.template import Origin

            # flatten the Django Context into a single dictionary.
            context_dict = {}
            if hasattr(context, 'dicts'):
                for d in context.dicts:
                    context_dict.update(d)
            else:
                context_dict = context
 
                # Django Debug Toolbar needs a RequestContext-like object in
                # order to inspect context.
                class FakeRequestContext:
                    dicts = [context]
                context = FakeRequestContext()

            # Used by debug_toolbar.
            if settings.TEMPLATE_DEBUG:
                from django.test import signals
                self.origin = Origin(self.filename)
                signals.template_rendered.send(sender=self, template=self,
                                               context=context)

            return self.template.render(**context_dict)

    class Loader(BaseLoader):

        is_usable = True

        def load_template(self, template_name, template_dirs=None):
            if hasattr(template_name, 'rsplit'):
                app = template_name.rsplit('/')[0]
                exclude_apps = getattr(settings, 'JINGO_EXCLUDE_APPS',
                                       EXCLUDE_APPS)
                if app in exclude_apps:
                    raise TemplateDoesNotExist(template_name)
            try:
                template = env.get_template(template_name)
                return AdapterTemplate(template), template.filename
            except jinja2.TemplateNotFound:
                raise TemplateDoesNotExist(template_name)
