from django import template

register = template.Library()

@register.inclusion_tag('app/tags/top_stories.html')
def top_stories():
    pass