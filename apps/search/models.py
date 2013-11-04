from django.db import models

from taggit.managers import TaggableManager


class FilterGroup(models.Model):
    """
    A way to group different kinds of filters from each other.
    """
    name = models.CharField(max_length=255)

    def __unicode__(self):
        return self.name


class Filter(models.Model):
    # the English name of the filter
    name = models.CharField(max_length=255, db_index=True)
    # the slug to be used in the URL
    slug = models.CharField(max_length=255, db_index=True)
    # the filter group, e.g. "Topic", "Skill level" etc
    group = models.ForeignKey(FilterGroup, related_name='filters')
    # the tags to filter for
    tags = TaggableManager()

    class Meta(object):
        unique_together = (('name', 'slug'),)

    def __unicode__(self):
        return self.name
