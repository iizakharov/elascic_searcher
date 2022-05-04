from django import template

from mainapp.forms import SearchForm


register = template.Library()


@register.inclusion_tag("./tags/search.html")
def search_form():
    return {'menu_search_form': SearchForm()}
