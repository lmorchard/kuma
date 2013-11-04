from django.contrib import admin

from .models import Filter, FilterGroup


class FilterAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'group')
    list_filter = ('group',)
    search_fields = ('name', 'slug')


admin.site.register(FilterGroup)
admin.site.register(Filter, FilterAdmin)
