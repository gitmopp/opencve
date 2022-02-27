import itertools
import json
import operator

from django.shortcuts import get_object_or_404
from django.db.models import Q
from django.views.generic import DetailView, ListView, TemplateView

from core.constants import PRODUCT_SEPARATOR
from core.models import Cve, Cwe, Vendor, Product
from core.utils import convert_cpes, get_cwes_details
from changes.models import Event


class HomeView(TemplateView):
    template_name = "core/home.html"


class CweListView(ListView):
    queryset = Cwe.objects.order_by("-name")
    context_object_name = "cwes"
    template_name = "core/cwe_list.html"
    paginate_by = 20


class CveListView(ListView):
    context_object_name = "cves"
    template_name = "core/cve_list.html"
    paginate_by = 20

    def get_queryset(self):
        query = Cve.objects.order_by("-updated_at")

        # Filter by keyword
        search = self.request.GET.get("search")
        if search:
            query = query.filter(
                Q(cve_id__icontains=search)
                | Q(summary__icontains=search)
                | Q(vendors__contains=search)
            )

        # Filter by CWE
        cwe = self.request.GET.get("cwe")
        if cwe:
            query = query.filter(cwes__contains=cwe)

        # Filter by CVSS score
        cvss = self.request.GET.get("cvss", "").lower()
        if cvss in [
            "empty",
            "low",
            "medium",
            "high",
            "critical",
        ]:
            if cvss == "empty":
                query = query.filter(cvss3__isnull=True)
            if cvss == "low":
                query = query.filter(Q(cvss3__gte=0) & Q(cvss3__lte=3.9))
            if cvss == "medium":
                query = query.filter(Q(cvss3__gte=4.0) & Q(cvss3__lte=6.9))
            if cvss == "high":
                query = query.filter(Q(cvss3__gte=7.0) & Q(cvss3__lte=8.9))
            if cvss == "critical":
                query = query.filter(Q(cvss3__gte=9.0) & Q(cvss3__lte=10.0))

        # Filter by Vendor and Product
        vendor_param = self.request.GET.get("vendor", "").replace(" ", "").lower()
        product_param = self.request.GET.get("product", "").replace(" ", "_").lower()

        if vendor_param:
            vendor = get_object_or_404(Vendor, name=vendor_param)
            query = query.filter(vendors__contains=vendor.name)

            if product_param:
                product = get_object_or_404(Product, name=product_param, vendor=vendor)
                query = query.filter(
                    vendors__contains=f"{vendor.name}{PRODUCT_SEPARATOR}{product.name}"
                )

        return query

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        vendor = self.request.GET.get("vendor")
        product = self.request.GET.get("product")
        if vendor:
            context["vendor"] = Vendor.objects.get(name=vendor)

            if product:
                context["product"] = Product.objects.get(
                    name=product, vendor=context["vendor"]
                )

        return context


class CveDetailView(DetailView):
    model = Cve
    slug_field = "cve_id"
    slug_url_kwarg = "cve_id"
    template_name = "core/cve_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["cve_dumped"] = json.dumps(context["cve"].json)

        # Add the events history
        events = Event.objects.filter(cve_id=context["cve"].id).order_by("-created_at")
        context["events_by_time"] = [
            (time, list(evs))
            for time, evs in (
                itertools.groupby(events, operator.attrgetter("created_at"))
            )
        ]

        # Add the associated Vendors and CWEs
        context["vendors"] = convert_cpes(context["cve"].json["configurations"])
        context["cwes"] = get_cwes_details(
            context["cve"].json["cve"]["problemtype"]["problemtype_data"][0][
                "description"
            ]
        )
        return context
