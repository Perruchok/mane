from django import template

register = template.Library()

@register.filter
def sum_list(value):
    """Returns the sum of a list."""
    if not isinstance(value, list):
        raise TypeError("Input value must be a list.")
    return sum(value)

@register.filter
def index(List, i):
    try:
        return List[i]
    except:
        return 0