from django import template
import json

register = template.Library()

@register.filter(name='highlight')
def highlight(p, searched):
    highlighted = p.replace(searched, f"<span class='highlight bg-warning text-light'>{searched}</span>")
    return highlighted


@register.filter(name='loads')
def loads(str):
    obj = json.loads(str)
    return obj


register.filter('highlight', highlight)
register.filter('loads', loads)