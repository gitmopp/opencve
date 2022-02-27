import hashlib

from django import template
from django.conf import settings
from django.urls import reverse
from django.utils.http import urlencode
from django.utils.safestring import mark_safe

from core.constants import PRODUCT_SEPARATOR
from core.utils import humanize as _humanize


register = template.Library()


def excerpt(objects, _type):
    """
    This function takes a flat list of vendors and products and returns
    the HTML code used in the CVEs list page.
    """
    output = ""

    if not objects:
        return output

    # Keep the objects of the requested type
    if _type == "products":
        objects = [o for o in objects if PRODUCT_SEPARATOR in o]
    else:
        objects = [o for o in objects if not PRODUCT_SEPARATOR in o]

    objects = sorted(objects)
    output += '<span class="badge badge-primary">{}</span> '.format(len(objects))

    # Keep the remains size and reduce the list
    remains = len(objects[settings.COUNT_EXCERPT :])

    if len(objects) > settings.COUNT_EXCERPT:
        objects = objects[: settings.COUNT_EXCERPT]

    # Construct the HTML
    for idx, obj in enumerate(objects):
        base_url = reverse("cves")

        if _type == "products":
            vendor, product = obj.split(PRODUCT_SEPARATOR)
            query_kwargs = urlencode({"vendor": vendor, "product": product})
            output += f"<a href='{base_url}?{query_kwargs}'>{humanize(product)}</a>"
        elif _type == "vendors":
            query_kwargs = urlencode({"vendor": obj})
            output += f"<a href='{base_url}?{query_kwargs}'>{humanize(obj)}</a>"
        """else:
            url = url_for("main.cves", tag=obj)
            tag = UserTag.query.filter_by(user_id=current_user.id, name=obj).first()
            output += f"<a href='{url}'><span class='label label-tag' style='background-color: {tag.color};'>{obj}</span></a>"""

        output += ", " if idx + 1 != len(objects) and _type != "tags" else " "

    if remains:
        output += "<i>and {} more</i>".format(remains)

    return output


def cvss(score):
    score = float(score)

    if 0 <= score <= 3.9:
        return ("bg-blue", "label-info")
    elif 4.0 <= score <= 6.9:
        return ("bg-yellow", "label-warning")
    elif 7.0 <= score <= 8.9:
        return ("bg-red", "label-danger")
    else:
        return ("bg-critical", "label-critical")


@register.filter(is_safe=True)
def vendors_excerpt(s):
    return mark_safe(excerpt(s, "vendors"))


@register.filter(is_safe=True)
def products_excerpt(s):
    return mark_safe(excerpt(s, "products"))


@register.filter
def cvss_bg(score):
    return cvss(score)[0]


@register.filter
def cvss_label(score):
    return cvss(score)[1]


@register.filter
def humanize(s):
    return _humanize(s)


@register.filter
def gravatar_url(email, size=40):
    return "https://www.gravatar.com/avatar/{}?{}".format(
        hashlib.md5(email.lower().encode("utf-8")).hexdigest(),
        urlencode({"s": str(size)}),
    )


@register.simple_tag
def metric_bg(version, type, value):
    metrics_v2 = {
        "AV": {
            "local": "label-default",
            "adjacent network": "label-warning",
            "network": "label-danger",
        },
        "AC": {
            "high": "label-default",
            "medium": "label-warning",
            "low": "label-danger",
        },
        "AU": {
            "multiple": "label-default",
            "single": "label-warning",
            "none": "label-danger",
        },
        "C": {
            "none": "label-default",
            "partial": "label-warning",
            "complete": "label-danger",
        },
        "I": {
            "none": "label-default",
            "partial": "label-warning",
            "complete": "label-danger",
        },
        "A": {
            "none": "label-default",
            "partial": "label-warning",
            "complete": "label-danger",
        },
    }

    metrics_v3 = {
        "AV": {
            "network": "label-danger",
            "adjacent": "label-warning",
            "local": "label-warning",
            "physical": "label-default",
        },
        "AC": {"low": "label-danger", "high": "label-warning"},
        "PR": {"none": "label-danger", "low": "label-warning", "high": "label-default"},
        "UI": {"none": "label-danger", "required": "label-warning"},
        "S": {"unchanged": "label-default", "changed": "label-danger"},
        "C": {"high": "label-danger", "low": "label-warning", "none": "label-default"},
        "I": {"high": "label-danger", "low": "label-warning", "none": "label-default"},
        "A": {"high": "label-danger", "low": "label-warning", "none": "label-default"},
    }
    versions = {"v2": metrics_v2, "v3": metrics_v3}

    try:
        value = versions[version][type][value.lower()]
    except KeyError:
        return ("label-default", "No description")

    return value


@register.filter
def get_conf_children(conf):
    if conf["operator"] == "AND":
        return conf["children"]
    return [conf]
